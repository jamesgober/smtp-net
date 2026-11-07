//! The NFR-14 soak: one message every 10 ms over a reused connection to a
//! loopback `TestServer`, a two-connection `Pool` fed by two threads beside
//! it, and a send to a misbehaving server every second (a different fault
//! each time). Live heap bytes, open descriptors, and threads are sampled
//! as it runs; the run fails if any of them grows, if a fault ends any way
//! but the expected one, or if a message reported sent did not arrive.
//!
//! Ignored by default. The 24-hour run, on Linux:
//!
//! ```text
//! SMTP_NET_SOAK_SECS=86400 cargo test --release --features testing --test soak -- --ignored --nocapture
//! ```
//!
//! `SMTP_NET_SOAK_SECS` defaults to 120. Descriptors and threads are read
//! from `/proc/self`; elsewhere only the heap is checked.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use smtp_net::{Client, Error, Fault, Message, Pool, Stage, TestServer};

struct Counting;

/// Heap bytes held by the whole process (allocated minus freed).
static LIVE: AtomicIsize = AtomicIsize::new(0);

// SAFETY: forwards to the system allocator; only counts bytes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new: usize) -> *mut u8 {
        LIVE.fetch_add(new as isize - layout.size() as isize, Ordering::Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.realloc(ptr, layout, new) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// The period of the main sender (NFR-14: one message per 10 ms).
const PERIOD: Duration = Duration::from_millis(10);
/// One send to a fault server every this many main sends (once a second).
const FAULT_EVERY: u64 = 100;
/// Heap growth allowed between the first and last third of a run, for
/// allocator and buffer jitter. A leak of one allocation per message grows
/// by megabytes an hour.
const HEAP_SLACK: isize = 1 << 20;
/// Descriptors or threads allowed above the first third's highest.
const COUNT_SLACK: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Expect {
    /// Delivered (the client reconnects by itself where it must).
    Sent,
    /// Refused, temporary, nothing possibly delivered.
    Temporary,
    /// Refused, permanent.
    Permanent,
    /// Refused after the end of the data: temporary and possibly delivered.
    PossiblyDelivered,
    /// Refused as a protocol violation of the server's (classified as the
    /// session says; only the failure is required).
    Failed,
}

struct FaultServer {
    name: &'static str,
    server: TestServer,
    expect: Expect,
    client: Option<Client>,
}

fn fault_servers() -> Vec<FaultServer> {
    let make = |name, fault, expect| FaultServer {
        name,
        server: TestServer::builder()
            .record(false)
            .fault(fault)
            .start()
            .unwrap(),
        expect,
        client: None,
    };
    vec![
        make(
            "close at DATA",
            Fault::CloseAt(Stage::Data),
            Expect::Temporary,
        ),
        make(
            "close after the end of data",
            Fault::CloseAfterDataEnd,
            Expect::PossiblyDelivered,
        ),
        make(
            "451 to RCPT",
            Fault::ReplyAt {
                stage: Stage::Rcpt,
                reply: "451 4.3.0 Try again later",
            },
            Expect::Temporary,
        ),
        make(
            "550 to MAIL",
            Fault::ReplyAt {
                stage: Stage::Mail,
                reply: "550 5.7.1 Not from you",
            },
            Expect::Permanent,
        ),
        make(
            "recipient refused",
            Fault::RejectRecipient(0),
            Expect::Permanent,
        ),
        make(
            "malformed reply to MAIL",
            Fault::MalformedReply(Stage::Mail),
            Expect::Failed,
        ),
        make(
            "extra reply to RCPT",
            Fault::ExtraReply(Stage::Rcpt),
            Expect::Failed,
        ),
        make(
            "oversized reply to EHLO",
            Fault::OversizedReply(Stage::Ehlo),
            Expect::Failed,
        ),
        make(
            "close after three messages",
            Fault::CloseAfterMessages(3),
            Expect::Sent,
        ),
        make(
            "1 ms round trip",
            Fault::RoundTrip(Duration::from_millis(1)),
            Expect::Sent,
        ),
    ]
}

fn outcome(result: &Result<(), Error>) -> Expect {
    match result {
        Ok(()) => Expect::Sent,
        Err(e) if e.possibly_delivered() => Expect::PossiblyDelivered,
        Err(e) if e.is_temporary() => Expect::Temporary,
        Err(_) => Expect::Permanent,
    }
}

impl FaultServer {
    /// Sends one message, connecting first when there is no open client;
    /// a failed client is dropped and the next send connects again.
    fn send(&mut self, msg: &Message) -> Result<(), Error> {
        let client = match self.client.as_mut() {
            Some(c) => c,
            None => self.client.insert(Client::connect(&self.server.server())?),
        };
        let r = client.send(msg).map(|_| ());
        if r.is_err() {
            self.client = None;
        }
        r
    }

    fn check(&mut self, msg: &Message) -> Option<String> {
        let r = self.send(msg);
        let got = outcome(&r);
        let ok = match self.expect {
            Expect::Failed => r.is_err(),
            want => got == want,
        };
        (!ok).then(|| format!("{}: expected {:?}, got {r:?}", self.name, self.expect))
    }
}

fn msg(i: u64) -> Message {
    let to = format!("user{}@example.org", i % 1000);
    if i % 2 == 0 {
        Message::text("no-reply@example.com", &to, "Soak", "Hello.\n.\nBye.\n").unwrap()
    } else {
        Message::html(
            "no-reply@example.com",
            &to,
            "Soak",
            "Hello.\n",
            "<p>Hello.</p>",
        )
        .unwrap()
    }
}

/// Open descriptors and threads of this process, where `/proc` has them.
fn os_counts() -> (Option<usize>, Option<usize>) {
    let fds = std::fs::read_dir("/proc/self/fd").ok().map(Iterator::count);
    let threads = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Threads:"))
                .and_then(|v| v.trim().parse().ok())
        });
    (fds, threads)
}

#[derive(Clone, Copy, Debug)]
struct Sample {
    secs: u64,
    heap: isize,
    fds: Option<usize>,
    threads: Option<usize>,
}

fn highest<T: Ord + Copy>(s: &[Sample], f: impl Fn(&Sample) -> Option<T>) -> Option<T> {
    s.iter().filter_map(f).max()
}

#[test]
#[ignore = "long-running; see the module documentation"]
fn soak() {
    let secs: u64 = std::env::var("SMTP_NET_SOAK_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(120);
    let run = Duration::from_secs(secs);
    // About 100 samples a run, at most one a minute.
    let every = Duration::from_secs((secs / 100).clamp(1, 60));

    let main = TestServer::builder().record(false).start().unwrap();
    let mut client = Client::connect(&main.server()).unwrap();
    let mut faults = fault_servers();

    let stop = Arc::new(AtomicBool::new(false));
    let pooled = Arc::new(AtomicUsize::new(0));
    let pool = Arc::new(Pool::new(main.server(), 2).unwrap());
    let workers: Vec<_> = (0..2u64)
        .map(|w| {
            let (pool, stop, pooled) = (pool.clone(), stop.clone(), pooled.clone());
            thread::spawn(move || {
                let mut i = w;
                while !stop.load(Ordering::Relaxed) {
                    pool.send(&msg(i)).unwrap();
                    pooled.fetch_add(1, Ordering::Relaxed);
                    i += 2;
                    thread::sleep(Duration::from_millis(50));
                }
            })
        })
        .collect();

    let start = Instant::now();
    let mut next = start;
    let mut next_sample = start;
    let (mut sent, mut late, mut fault_sends) = (0u64, 0u64, 0u64);
    let mut wrong: Vec<String> = Vec::new();
    let mut wrong_count = 0u64;
    let mut samples: Vec<Sample> = Vec::new();
    println!("soak: {secs} s, a sample every {} s", every.as_secs());
    while start.elapsed() < run {
        client.send(&msg(sent)).unwrap();
        sent += 1;
        if sent % FAULT_EVERY == 0 {
            let k = ((sent / FAULT_EVERY) as usize) % faults.len();
            fault_sends += 1;
            if let Some(w) = faults[k].check(&msg(sent)) {
                wrong_count += 1;
                if wrong.len() < 20 {
                    wrong.push(w);
                }
            }
        }
        let now = Instant::now();
        if now >= next_sample {
            let (fds, threads) = os_counts();
            let s = Sample {
                secs: start.elapsed().as_secs(),
                heap: LIVE.load(Ordering::Relaxed),
                fds,
                threads,
            };
            println!(
                "t={:>6}s sent={sent} pooled={} faults={fault_sends} wrong={wrong_count} late={late} heap={} fds={:?} threads={:?}",
                s.secs,
                pooled.load(Ordering::Relaxed),
                s.heap,
                s.fds,
                s.threads
            );
            samples.push(s);
            next_sample += every;
        }
        next += PERIOD;
        match next.checked_duration_since(Instant::now()) {
            Some(wait) => thread::sleep(wait),
            None => {
                late += 1;
                // Behind by more than a second (a loaded machine): start
                // the schedule again instead of sending in a burst.
                if Instant::now() - next > Duration::from_secs(1) {
                    next = Instant::now();
                }
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
    for w in workers {
        w.join().unwrap();
    }
    client.close().unwrap();
    let pooled = pooled.load(Ordering::Relaxed) as u64;
    // Every message reported sent arrived.
    assert_eq!(main.messages() as u64, sent + pooled, "messages lost");

    // Skip the first tenth (warm-up), then compare the first and last
    // thirds of what is left.
    let rest = &samples[samples.len() / 10..];
    let third = (rest.len() / 3).max(1);
    let (first, last) = (&rest[..third], &rest[rest.len() - third..]);
    let heap = (
        highest(first, |s| Some(s.heap)),
        highest(last, |s| Some(s.heap)),
    );
    let fds = (highest(first, |s| s.fds), highest(last, |s| s.fds));
    let threads = (highest(first, |s| s.threads), highest(last, |s| s.threads));
    println!(
        "soak done: {} s, {sent} sent, {pooled} pooled, {fault_sends} to fault servers, {late} late; highest heap {:?} then {:?}, fds {:?} then {:?}, threads {:?} then {:?}",
        start.elapsed().as_secs(),
        heap.0,
        heap.1,
        fds.0,
        fds.1,
        threads.0,
        threads.1
    );
    assert!(
        wrong.is_empty(),
        "{wrong_count} faults ended wrongly: {wrong:#?}"
    );
    if let (Some(a), Some(b)) = heap {
        assert!(b <= a + HEAP_SLACK, "heap grew from {a} to {b}");
    }
    if let (Some(a), Some(b)) = fds {
        assert!(b <= a + COUNT_SLACK, "descriptors grew from {a} to {b}");
    }
    if let (Some(a), Some(b)) = threads {
        assert!(b <= a + COUNT_SLACK, "threads grew from {a} to {b}");
    }
}
