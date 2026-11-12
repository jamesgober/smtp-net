//! Pacing below a host's hourly cap (cPanel accepts mail over its cap and
//! then queues or drops it, so the client has to stay under it).
//!
//! ```text
//! cargo run --example hourly_limit
//! ```

use smtp_net::{Address, Admission, Envelope, HourlyLimit, SendGate};

fn main() -> Result<(), smtp_net::Error> {
    // Leave headroom below the host's cap for operator mail.
    let gate = HourlyLimit::recipients(3);
    let envelope = Envelope::new(
        Address::parse("no-reply@example.com")?,
        &[Address::parse("user@example.org")?],
    )?;
    let start = 1_700_000_000_000u64;
    for i in 0..4u64 {
        let now = start + i * 60_000;
        match gate.admit(&envelope, now) {
            Admission::Admit => println!("message {i}: send now ({} left)", gate.remaining(now)),
            Admission::RetryAfter(d) => println!("message {i}: delay the job by {} s", d.as_secs()),
            _ => {}
        }
    }
    // With a Server: Server::builder(host, security).gate(HourlyLimit::recipients(450)).build()
    Ok(())
}
