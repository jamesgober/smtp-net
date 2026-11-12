//! A driver for the sans-IO `Session` over a plain `std::net::TcpStream`,
//! sending one message to the crate's `TestServer`. Any transport can drive
//! a session this way.
//!
//! ```text
//! cargo run --example sans_io_driver --features testing
//! ```

use std::{
    io::{Read, Write},
    net::TcpStream,
    time::Instant,
};

use smtp_net::protocol::{BodyFlags, Event, Millis, Session, SessionConfig, SessionSecurity};
use smtp_net::testing::TestServer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServer::start()?;
    let msg = smtp_net::Message::text(
        "a@example.com",
        "b@example.org",
        "Hello",
        "Sent by a hand-written driver.",
    )?;
    let prepared = msg.prepare()?;

    let start = Instant::now();
    let now = || Millis(start.elapsed().as_millis() as u64);
    let mut socket = TcpStream::connect(("127.0.0.1", server.port()))?;
    let mut config = SessionConfig::default();
    config.security = SessionSecurity::Plaintext {
        peer_is_loopback: socket.peer_addr()?.ip().is_loopback(),
    };
    let mut session = Session::new(config, now())?;

    let mut buf = [0u8; 4096];
    let mut body: Option<&[u8]> = None;
    let mut sent = false;
    loop {
        if let Some(rest) = body {
            let n = session.body(rest, now())?;
            body = if n == rest.len() {
                None
            } else {
                Some(&rest[n..])
            };
            if body.is_none() {
                session.end_body(now())?;
            }
        }
        let out = session.transmit();
        if !out.is_empty() {
            socket.write_all(out)?;
            let n = out.len();
            session.transmitted(n);
        }
        while let Some(event) = session.poll_event() {
            match event {
                Event::Ready { .. } if !sent => {
                    sent = true;
                    let flags = BodyFlags::new(prepared.has_8bit(), prepared.needs_smtputf8());
                    session.begin(
                        prepared.envelope(),
                        flags,
                        prepared.bytes().len() as u64,
                        now(),
                    )?;
                }
                Event::BodyWanted => body = Some(prepared.bytes()),
                Event::Delivered { reply, .. } => {
                    println!("delivered: {}", reply.text_lossy());
                    session.quit(now())?;
                }
                Event::TransactionFailed(e) => return Err(e.into()),
                Event::Closed { error } => return error.map_or(Ok(()), |e| Err(e.into())),
                _ => {}
            }
        }
        if body.is_none() && session.wants_read() {
            if let Some(deadline) = session.deadline() {
                let left = deadline.0.saturating_sub(now().0).max(1);
                socket.set_read_timeout(Some(std::time::Duration::from_millis(left)))?;
            }
            match socket.read(&mut buf) {
                Ok(0) => {
                    return Err(session
                        .connection_lost(smtp_net::ErrorKind::ConnectionClosed)
                        .into());
                }
                Ok(n) => {
                    session.receive(&buf[..n], now())?;
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    session.on_timeout(now())?;
                }
                Err(e) => {
                    return Err(session
                        .connection_lost(smtp_net::ErrorKind::Io(e.kind()))
                        .into());
                }
            }
        }
    }
}
