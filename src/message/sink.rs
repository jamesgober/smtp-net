//! Serialization sinks (D-032).

use alloc::vec::Vec;

use crate::error::SinkError;

/// Where serialized message bytes go. Usable without `std`.
///
/// # Examples
///
/// ```
/// use smtp_net::{CountingSink, Sink};
/// let mut count = CountingSink::default();
/// count.write(b"hello")?;
/// assert_eq!(count.bytes, 5);
/// # Ok::<(), smtp_net::SinkError>(())
/// ```
pub trait Sink {
    /// Appends all of `bytes`, or fails.
    ///
    /// # Errors
    ///
    /// [`SinkError::Full`] when there is no room; `SinkError::Io` when the
    /// underlying writer failed.
    fn write(&mut self, bytes: &[u8]) -> Result<(), SinkError>;
}

/// Never refuses: the message size budget is checked against
/// [`Message::encoded_len`](crate::Message::encoded_len) before writing.
impl Sink for Vec<u8> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), SinkError> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}

impl<S: Sink + ?Sized> Sink for &mut S {
    fn write(&mut self, bytes: &[u8]) -> Result<(), SinkError> {
        (**self).write(bytes)
    }
}

/// Counts bytes without storing them.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CountingSink {
    /// Bytes written so far.
    pub bytes: u64,
}

impl Sink for CountingSink {
    fn write(&mut self, bytes: &[u8]) -> Result<(), SinkError> {
        self.bytes = self.bytes.saturating_add(bytes.len() as u64);
        Ok(())
    }
}

/// Adapter from [`std::io::Write`] to [`Sink`].
///
/// # Examples
///
/// ```
/// use smtp_net::{IoSink, Sink};
/// let mut sink = IoSink(Vec::new());
/// sink.write(b"abc")?;
/// assert_eq!(sink.0, b"abc");
/// # Ok::<(), smtp_net::SinkError>(())
/// ```
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct IoSink<W: std::io::Write>(pub W);

#[cfg(feature = "std")]
impl<W: std::io::Write> Sink for IoSink<W> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), SinkError> {
        self.0.write_all(bytes).map_err(|e| SinkError::Io(e.kind()))
    }
}

/// A fixed buffer that refuses what does not fit.
#[cfg(test)]
pub(crate) struct SliceSink<'a> {
    pub(crate) buf: &'a mut [u8],
    pub(crate) len: usize,
}

#[cfg(test)]
impl Sink for SliceSink<'_> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), SinkError> {
        let end = self.len.checked_add(bytes.len()).ok_or(SinkError::Full)?;
        let dst = self.buf.get_mut(self.len..end).ok_or(SinkError::Full)?;
        dst.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slice_sink_refuses_overflow_without_writing() {
        let mut buf = [0u8; 4];
        let mut s = SliceSink {
            buf: &mut buf,
            len: 0,
        };
        s.write(b"abc").unwrap();
        assert_eq!(s.write(b"de"), Err(SinkError::Full));
        assert_eq!(s.len, 3);
    }

    #[test]
    fn test_counting_sink_saturates() {
        let mut c = CountingSink {
            bytes: u64::MAX - 1,
        };
        c.write(b"abc").unwrap();
        assert_eq!(c.bytes, u64::MAX);
    }
}
