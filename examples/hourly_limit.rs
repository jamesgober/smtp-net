//! Pacing below a host's hourly cap (cPanel accepts mail over its cap and
//! then queues or drops it, so the client has to stay under it).
//!
//! ```text
//! cargo run --example hourly_limit
//! ```

use smtp_net::{Admission, HourlyLimit, SendGate};

fn main() {
    // Leave headroom below the host's cap for operator mail.
    let gate = HourlyLimit::recipients(3);
    let start = 1_700_000_000_000u64;
    for (i, recipients) in [1u32, 1, 1, 1].into_iter().enumerate() {
        let now = start + i as u64 * 60_000;
        match gate.admit(recipients, now) {
            Admission::Admit => println!("message {i}: send now ({} left)", gate.remaining(now)),
            Admission::RetryAfter(d) => println!("message {i}: delay the job by {} s", d.as_secs()),
            _ => {}
        }
    }
    // With a Server: Server::builder(host, security).gate(HourlyLimit::recipients(450)).build()
}
