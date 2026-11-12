//! The job-system path: build and serialize once in the request handler,
//! store the payload, send it from a worker, and map the outcome to retry
//! or dead-letter. Runs against the crate's `TestServer`.
//!
//! ```text
//! cargo run --example prepared_job --features testing
//! ```

use smtp_net::testing::{Fault, TestServer};
use smtp_net::{Message, PreparedMessage, Server, Stage};

#[derive(Debug)]
enum JobOutcome {
    Done,
    RetryLater,
    PossibleDuplicate,
    DeadLetter,
}

/// What a job handler does with a stored payload.
fn send_email(server: &Server, payload: &[u8]) -> JobOutcome {
    let prepared = match PreparedMessage::decode(payload) {
        Ok(p) => p,
        // A damaged payload is refused, never sent.
        Err(_) => return JobOutcome::DeadLetter,
    };
    match smtp_net::send_prepared(server, &prepared) {
        Ok(_) => JobOutcome::Done,
        Err(e) if e.possibly_delivered() => JobOutcome::PossibleDuplicate,
        Err(e) if e.is_temporary() => JobOutcome::RetryLater,
        Err(_) => JobOutcome::DeadLetter,
    }
}

fn main() -> Result<(), smtp_net::Error> {
    // In the request handler: build, prepare, encode; store `payload` with the job.
    let msg = Message::text(
        "Example <no-reply@example.com>",
        "user@example.org",
        "Confirm your email address",
        "Open this link to confirm: https://example.com/confirm/abc123",
    )?;
    let payload = msg.prepare()?.encode();
    println!("payload: {} octets for {}", payload.len(), msg.message_id());

    // In the worker: a busy server first, then a healthy one.
    let busy = TestServer::builder()
        .fault(Fault::ReplyAt {
            stage: Stage::Mail,
            reply: "451 4.3.0 try later",
        })
        .start()?;
    println!("first attempt: {:?}", send_email(&busy.server(), &payload));
    let ok = TestServer::start()?;
    println!("retry: {:?}", send_email(&ok.server(), &payload));
    let mut damaged = payload.clone();
    damaged[12] ^= 1;
    println!("damaged payload: {:?}", send_email(&ok.server(), &damaged));
    Ok(())
}
