//! `Pool` against `TestServer`: many threads on few connections, a dropped
//! connection replaced, the wait limit (PLAN 12.2 item 87).

use std::sync::Arc;
use std::time::Duration;

use smtp_net::{ErrorKind, Fault, Message, Pool, Stage, TestServer};

fn msg(i: usize) -> Message {
    Message::text(
        "no-reply@example.com",
        &format!("user{i}@example.org"),
        "Pooled",
        "Hello.\n",
    )
    .unwrap()
}

#[test]
fn test_64_threads_share_one_connection() {
    let server = TestServer::start().unwrap();
    let pool = Arc::new(Pool::new(server.server(), 1).unwrap());
    let threads: Vec<_> = (0..64)
        .map(|i| {
            let pool = pool.clone();
            std::thread::spawn(move || pool.send(&msg(i)).map(|_| ()))
        })
        .collect();
    for t in threads {
        t.join().unwrap().unwrap();
    }
    assert_eq!(server.received().len(), 64);
    assert_eq!(server.connections(), 1);
    assert_eq!(pool.idle(), 1);
}

#[test]
fn test_connections_never_exceed_the_limit() {
    let server = TestServer::start().unwrap();
    // Every connection accepted is counted, so none may reach the
    // 100-message reconnect: under load one slot can carry most of the 128.
    let s = server
        .server_builder()
        .max_messages_per_connection(1000)
        .build()
        .unwrap();
    let pool = Arc::new(Pool::new(s, 4).unwrap());
    let threads: Vec<_> = (0..16)
        .map(|t| {
            let pool = pool.clone();
            std::thread::spawn(move || {
                for i in 0..8 {
                    pool.send(&msg(t * 8 + i)).unwrap();
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(server.received().len(), 128);
    assert!(server.connections() <= 4, "{}", server.connections());
    assert!(pool.idle() >= 1 && pool.idle() <= 4);
}

#[test]
fn test_a_failed_connection_is_dropped_and_replaced() {
    let server = TestServer::builder()
        .fault(Fault::CloseAt(Stage::Rcpt))
        .start()
        .unwrap();
    let pool = Pool::new(server.server(), 1).unwrap();
    assert!(pool.send(&msg(0)).is_err());
    assert_eq!(pool.idle(), 0, "the failed connection is not returned");
    assert!(pool.send(&msg(1)).is_err());
    assert_eq!(server.connections(), 2, "a new connection each time");

    // A server that closes after two messages: the pool keeps going.
    let server = TestServer::builder()
        .fault(Fault::CloseAfterMessages(2))
        .start()
        .unwrap();
    let pool = Pool::new(server.server(), 1).unwrap();
    for i in 0..5 {
        pool.send(&msg(i)).unwrap();
    }
    assert_eq!(server.received().len(), 5);
    assert_eq!(server.connections(), 3);
}

#[test]
fn test_busy_pool_times_out_with_pool_exhausted() {
    let server = TestServer::builder()
        .fault(Fault::DelayAt {
            stage: Stage::DataEnd,
            by: Duration::from_millis(800),
        })
        .start()
        .unwrap();
    let pool = Arc::new(
        Pool::new(server.server(), 1)
            .unwrap()
            .wait_limit(Duration::from_millis(100)),
    );
    let p = pool.clone();
    let slow = std::thread::spawn(move || p.send(&msg(0)));
    // The first send holds the only slot once its connection is up (a
    // fixed sleep raced on a loaded machine); its end of data waits 800 ms.
    let up = std::time::Instant::now();
    while server.connections() == 0 {
        assert!(
            up.elapsed() < Duration::from_secs(10),
            "first send never connected"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let e = pool.send(&msg(1)).unwrap_err();
    assert_eq!(e.kind(), &ErrorKind::PoolExhausted, "{e:?}");
    assert!(e.is_temporary());
    slow.join().unwrap().unwrap();
    assert_eq!(server.received().len(), 1);
}
