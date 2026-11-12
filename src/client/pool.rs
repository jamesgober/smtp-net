//! `Pool`: a bounded set of connections to one server, shared by threads.

use std::sync::{Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use super::slots::{MAX_SLOTS, Slots};
use super::{Client, Report, Server};
use crate::error::{ConfigError, Error, ErrorKind};
use crate::message::{Message, prepared::PreparedMessage};

/// How long a send waits for a free connection by default.
const DEFAULT_WAIT: Duration = Duration::from_secs(10);

/// At most `max_connections` connections to one [`Server`], reused across
/// threads. `Send + Sync`: share it with an `Arc`.
///
/// A send checks out a free connection (one already open first), opens one
/// when the slot has none, and returns it afterwards; a connection that
/// failed is dropped, not returned. A connection idle past the server's
/// idle limit is replaced on checkout; there is no timer thread. When every
/// connection stays busy past the wait limit, the send fails with
/// `PoolExhausted` (temporary).
///
/// # Examples
///
/// ```no_run
/// use std::sync::Arc;
/// let pool = Arc::new(smtp_net::Pool::new(smtp_net::Server::local(), 4)?);
/// let workers: Vec<_> = (0..8)
///     .map(|i| {
///         let pool = pool.clone();
///         std::thread::spawn(move || {
///             let to = format!("user{i}@example.org");
///             let msg = smtp_net::Message::text("no-reply@example.com", &to, "Hi", "Hello")?;
///             pool.send(&msg)
///         })
///     })
///     .collect();
/// for w in workers {
///     w.join().unwrap()?;
/// }
/// # Ok::<(), smtp_net::Error>(())
/// ```
pub struct Pool {
    server: Server,
    clients: Box<[Mutex<Option<Client>>]>,
    slots: Slots,
    wait: Duration,
    /// Released-slot count, for waiters (no lost wake-up).
    released: Mutex<u64>,
    freed: Condvar,
}

impl core::fmt::Debug for Pool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pool")
            .field("server", &self.server)
            .field("max_connections", &self.clients.len())
            .field("idle", &self.idle())
            .finish()
    }
}

/// Returns the slot even if a send panics.
struct Checkout<'a> {
    pool: &'a Pool,
    slot: usize,
    open: bool,
}

impl Drop for Checkout<'_> {
    fn drop(&mut self) {
        self.pool.slots.release(self.slot, self.open);
        let mut n = self
            .pool
            .released
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *n = n.wrapping_add(1);
        self.pool.freed.notify_one();
    }
}

impl Pool {
    /// A pool of at most `max_connections` (1 to 64) connections. Nothing
    /// is opened until the first send.
    ///
    /// # Errors
    ///
    /// `Config(PoolSize)`.
    pub fn new(server: Server, max_connections: usize) -> Result<Pool, Error> {
        if !(1..=MAX_SLOTS).contains(&max_connections) {
            return Err(ConfigError::PoolSize.into());
        }
        Ok(Pool {
            server,
            clients: (0..max_connections).map(|_| Mutex::new(None)).collect(),
            slots: Slots::new(max_connections),
            wait: DEFAULT_WAIT,
            released: Mutex::new(0),
            freed: Condvar::new(),
        })
    }

    /// How long a send waits for a free connection (default 10 s).
    #[must_use]
    pub fn wait_limit(mut self, wait: Duration) -> Pool {
        self.wait = wait;
        self
    }

    /// Sends a built message (signed by the server's DKIM signers).
    ///
    /// # Errors
    ///
    /// Every send error, and `PoolExhausted`.
    pub fn send(&self, message: &Message) -> Result<Report, Error> {
        self.send_prepared(&self.server.prepare(message)?)
    }

    /// Sends prepared bytes as they are.
    ///
    /// # Errors
    ///
    /// Every send error, and `PoolExhausted`.
    pub fn send_prepared(&self, message: &PreparedMessage) -> Result<Report, Error> {
        let total = self.server.timeouts.total.map(|t| Instant::now() + t);
        let mut checkout = self.checkout()?;
        let mut guard = self
            .clients
            .get(checkout.slot)
            .ok_or_else(|| Error::new(ErrorKind::PoolExhausted))?
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let client = match guard.take() {
            Some(c) => c,
            None => match Client::connect_by(&self.server, total) {
                Ok(c) => c,
                Err(e) => {
                    let failed = Err(e);
                    self.server.observe(message, &failed);
                    return failed;
                }
            },
        };
        let mut client = client;
        let result = client.send_by(message, total);
        // A failed connection is dropped; a healthy one goes back.
        if client.is_open() {
            *guard = Some(client);
            checkout.open = true;
        }
        drop(guard);
        drop(checkout);
        result
    }

    fn checkout(&self) -> Result<Checkout<'_>, Error> {
        let deadline = Instant::now() + self.wait;
        loop {
            let seen = *self.released.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(slot) = self.slots.acquire() {
                return Ok(Checkout {
                    pool: self,
                    slot,
                    open: false,
                });
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Error::new(ErrorKind::PoolExhausted));
            }
            let n = self.released.lock().unwrap_or_else(PoisonError::into_inner);
            let _ = self
                .freed
                .wait_timeout_while(n, deadline - now, |n| *n == seen)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Open connections not in use.
    #[must_use]
    pub fn idle(&self) -> usize {
        self.slots.idle()
    }

    /// The server this pool sends to.
    #[must_use]
    pub fn server(&self) -> &Server {
        &self.server
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_is_send_and_sync() {
        fn both<T: Send + Sync>() {}
        both::<Pool>();
    }

    #[test]
    fn test_pool_size_checked() {
        assert!(Pool::new(Server::local(), 0).is_err());
        assert!(Pool::new(Server::local(), 65).is_err());
        let p = Pool::new(Server::local(), 64).unwrap();
        assert_eq!(p.idle(), 0);
    }
}
