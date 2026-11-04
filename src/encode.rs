//! Transfer encodings: base64 and quoted-printable (RFC 2045 6.7 and 6.8),
//! and the base32 text used for generated ids and boundaries.
//!
//! These stay in smtp-net until the first-party encode-lib publishes them
//! (D-015); the public functions then become re-exports with the same
//! signatures.

use crate::error::{Error, ErrorKind};

/// Characters per encoded line, before the CRLF (RFC 2045 6.7 and 6.8).
pub const MIME_LINE_LENGTH: usize = 76;

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Input octets per full base64 line (76 characters).
pub(crate) const B64_LINE_INPUT: usize = MIME_LINE_LENGTH / 4 * 3;

/// Exact length of [`base64_encode_lines`] output for `n` input octets.
#[must_use]
pub const fn base64_encoded_len(n: u64) -> u64 {
    let chars = n.div_ceil(3) * 4;
    if chars == 0 {
        return 0;
    }
    let lines = chars.div_ceil(MIME_LINE_LENGTH as u64);
    chars + 2 * (lines - 1)
}

/// Encodes `input` as base64 (standard alphabet, padded) into `out`, with a
/// CRLF after every 76 characters and none after the last line. Returns the
/// number of bytes written.
///
/// # Errors
///
/// [`ErrorKind::BufferTooSmall`] when `out` is shorter than
/// [`base64_encoded_len`]; nothing useful is written then.
///
/// # Examples
///
/// ```
/// let mut out = [0u8; 16];
/// let n = smtp_net::base64_encode_lines(b"hello", &mut out)?;
/// assert_eq!(&out[..n], b"aGVsbG8=");
/// # Ok::<(), smtp_net::Error>(())
/// ```
pub fn base64_encode_lines(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let need = usize::try_from(base64_encoded_len(input.len() as u64))
        .map_err(|_| Error::new(ErrorKind::BufferTooSmall))?;
    let Some(out) = out.get_mut(..need) else {
        return Err(Error::new(ErrorKind::BufferTooSmall));
    };
    let mut at = 0usize;
    let mut first = true;
    for line in input.chunks(B64_LINE_INPUT) {
        if !first {
            put(out, &mut at, b"\r\n");
        }
        first = false;
        let mut buf = [0u8; MIME_LINE_LENGTH];
        let n = base64_line(line, &mut buf);
        put(out, &mut at, buf.get(..n).unwrap_or(&[]));
    }
    Ok(at)
}

fn put(out: &mut [u8], at: &mut usize, bytes: &[u8]) {
    if let Some(dst) = out.get_mut(*at..*at + bytes.len()) {
        dst.copy_from_slice(bytes);
    }
    *at += bytes.len();
}

/// Encodes at most 57 octets into one base64 line of at most 76 characters.
pub(crate) fn base64_line(input: &[u8], out: &mut [u8; MIME_LINE_LENGTH]) -> usize {
    let mut n = 0;
    for chunk in input.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let v = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        let chars = [
            b64((v >> 18) & 63),
            b64((v >> 12) & 63),
            if chunk.len() > 1 {
                b64((v >> 6) & 63)
            } else {
                b'='
            },
            if chunk.len() > 2 { b64(v & 63) } else { b'=' },
        ];
        if let Some(dst) = out.get_mut(n..n + 4) {
            dst.copy_from_slice(&chars);
        }
        n += 4;
    }
    n
}

fn b64(i: u32) -> u8 {
    B64.get(i as usize).copied().unwrap_or(b'A')
}

/// Writes `bytes` as unpadded lowercase base32 (RFC 4648 alphabet) into `out`.
/// `out` must hold `ceil(bytes.len() * 8 / 5)` characters; extra room is untouched.
pub(crate) fn base32(bytes: &[u8], out: &mut [u8]) -> usize {
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut n = 0usize;
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            if let Some(d) = out.get_mut(n) {
                *d = B32
                    .get(((acc >> bits) & 31) as usize)
                    .copied()
                    .unwrap_or(b'a');
            }
            n += 1;
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        if let Some(d) = out.get_mut(n) {
            *d = B32
                .get(((acc << (5 - bits)) & 31) as usize)
                .copied()
                .unwrap_or(b'a');
        }
        n += 1;
    }
    n
}

/// Decodes strict base64 (standard alphabet, padded, no whitespace) into
/// `out`, appending. Used for AUTH challenges; budgets are the caller's.
pub(crate) fn base64_decode(input: &[u8], out: &mut alloc::vec::Vec<u8>) -> Result<(), ()> {
    if input.len() % 4 != 0 {
        return Err(());
    }
    let val = |c: u8| -> Result<u32, ()> {
        match c {
            b'A'..=b'Z' => Ok(u32::from(c - b'A')),
            b'a'..=b'z' => Ok(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Ok(u32::from(c - b'0') + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(()),
        }
    };
    let quads = input.len() / 4;
    for (i, q) in input.chunks(4).enumerate() {
        let last = i + 1 == quads;
        let (a, b, c, d) = (
            q.first().copied().unwrap_or(0),
            q.get(1).copied().unwrap_or(0),
            q.get(2).copied().unwrap_or(0),
            q.get(3).copied().unwrap_or(0),
        );
        let pad = match (c, d) {
            (b'=', b'=') if last => 2,
            (_, b'=') if last => 1,
            _ => 0,
        };
        if pad < 2 && c == b'=' {
            return Err(());
        }
        let n = (val(a)? << 18)
            | (val(b)? << 12)
            | (if pad == 2 { 0 } else { val(c)? << 6 })
            | (if pad >= 1 { 0 } else { val(d)? });
        // Non-canonical padding bits are refused: one text, one meaning.
        if (pad == 2 && n & 0xffff != 0) || (pad == 1 && n & 0xff != 0) {
            return Err(());
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad == 0 {
            out.push(n as u8);
        }
    }
    Ok(())
}

/// Encodes `input` as one unbroken base64 string, appended to `out`.
pub(crate) fn base64_append(input: &[u8], out: &mut alloc::vec::Vec<u8>) {
    let mut buf = [0u8; MIME_LINE_LENGTH];
    for line in input.chunks(B64_LINE_INPUT) {
        let n = base64_line(line, &mut buf);
        out.extend_from_slice(buf.get(..n).unwrap_or(&[]));
    }
}

/// CRC-32C (Castagnoli, reflected polynomial 0x82F63B78), table-driven (D-028).
pub(crate) fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        let i = usize::from((crc as u8) ^ b);
        crc = (crc >> 8) ^ CRC32C_TABLE.get(i).copied().unwrap_or(0);
    }
    !crc
}

#[allow(clippy::indexing_slicing)] // const evaluation: the index is below 256
const CRC32C_TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0x82F6_3B78
            } else {
                c >> 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

/// Streaming state for [`quoted_printable_encode`].
///
/// Holds what the encoder cannot decide yet: whitespace that must be encoded
/// if a line break follows it, the start of a line that may turn out to be
/// `From `, and a CR that may start a CRLF.
#[derive(Clone, Debug, Default)]
pub struct QpState {
    col: usize,
    pending_ws: Option<u8>,
    pending_cr: bool,
    /// Bytes of "From" held at the start of a line (0 to 4).
    from: u8,
    mid_line: bool,
}

impl QpState {
    /// A state for the start of a text.
    #[must_use]
    pub fn new() -> QpState {
        QpState::default()
    }
}

/// Encodes `input` as quoted-printable (RFC 2045 6.7) into `out`, continuing
/// from `state`; returns the number of bytes written. Call it again with the
/// next chunk and the same state, then once with an empty `input` and
/// `finish = true`... see [`quoted_printable_finish`].
///
/// Encoded lines are at most 76 characters with `=` soft breaks; `=` and
/// non-printable octets are `=XX`; a space or tab before a line break is
/// encoded; a line starting with `.` starts `=2E` and one starting with
/// `From ` starts `=46rom ` (so dot handling and mbox readers cannot change
/// it); LF and CRLF in the input become CRLF line breaks; a CR not followed
/// by LF is `=0D`.
///
/// # Errors
///
/// [`ErrorKind::BufferTooSmall`] when `out` cannot hold the output; the
/// state is then unspecified. `3 * input.len() + 3 * (input.len() / 25) + 16`
/// octets always suffice.
///
/// # Examples
///
/// ```
/// use smtp_net::{quoted_printable_encode, quoted_printable_finish, QpState};
/// let mut state = QpState::new();
/// let mut out = [0u8; 64];
/// let mut n = quoted_printable_encode("Caf\u{e9} = ok \n.end".as_bytes(), &mut out, &mut state)?;
/// n += quoted_printable_finish(&mut out[n..], &mut state)?;
/// assert_eq!(&out[..n], b"Caf=C3=A9 =3D ok=20\r\n=2Eend");
/// # Ok::<(), smtp_net::Error>(())
/// ```
pub fn quoted_printable_encode(
    input: &[u8],
    out: &mut [u8],
    state: &mut QpState,
) -> Result<usize, Error> {
    let mut w = SliceWriter {
        out,
        at: 0,
        overflow: false,
    };
    qp_push(state, input, &mut |b| w.write(b));
    w.done()
}

/// Flushes what `state` still holds at the end of the text; returns the bytes written.
///
/// # Errors
///
/// [`ErrorKind::BufferTooSmall`] when `out` is shorter than 16 octets and the
/// state holds output.
pub fn quoted_printable_finish(out: &mut [u8], state: &mut QpState) -> Result<usize, Error> {
    let mut w = SliceWriter {
        out,
        at: 0,
        overflow: false,
    };
    qp_finish(state, &mut |b| w.write(b));
    w.done()
}

struct SliceWriter<'a> {
    out: &'a mut [u8],
    at: usize,
    overflow: bool,
}

impl SliceWriter<'_> {
    fn write(&mut self, bytes: &[u8]) {
        match self.out.get_mut(self.at..self.at + bytes.len()) {
            Some(dst) if !self.overflow => {
                dst.copy_from_slice(bytes);
                self.at += bytes.len();
            }
            _ => self.overflow = true,
        }
    }

    fn done(self) -> Result<usize, Error> {
        if self.overflow {
            Err(Error::new(ErrorKind::BufferTooSmall))
        } else {
            Ok(self.at)
        }
    }
}

const SOFT_LIMIT: usize = MIME_LINE_LENGTH - 1;

fn qp_token(state: &mut QpState, token: &[u8], emit: &mut impl FnMut(&[u8])) {
    if state.col + token.len() > SOFT_LIMIT {
        emit(b"=\r\n");
        state.col = 0;
    }
    emit(token);
    state.col += token.len();
    state.mid_line = true;
}

fn qp_hex(state: &mut QpState, b: u8, emit: &mut impl FnMut(&[u8])) {
    let t = [
        b'=',
        HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0'),
        HEX.get(usize::from(b & 15)).copied().unwrap_or(b'0'),
    ];
    qp_token(state, &t, emit);
}

fn qp_flush_from(state: &mut QpState, emit: &mut impl FnMut(&[u8])) {
    let held = usize::from(state.from);
    state.from = 0;
    for &b in b"From".get(..held).unwrap_or(&[]) {
        qp_token(state, &[b], emit);
    }
}

fn qp_flush_ws(state: &mut QpState, encode: bool, emit: &mut impl FnMut(&[u8])) {
    if let Some(ws) = state.pending_ws.take() {
        if encode {
            qp_hex(state, ws, emit);
        } else {
            qp_token(state, &[ws], emit);
        }
    }
}

fn qp_line_break(state: &mut QpState, emit: &mut impl FnMut(&[u8])) {
    qp_flush_from(state, emit);
    qp_flush_ws(state, true, emit);
    emit(b"\r\n");
    state.col = 0;
    state.mid_line = false;
}

fn qp_byte(state: &mut QpState, b: u8, emit: &mut impl FnMut(&[u8])) {
    if b == b'\n' {
        qp_line_break(state, emit);
        return;
    }
    // "From " detection at the start of a line.
    if !state.mid_line && state.pending_ws.is_none() {
        let held = usize::from(state.from);
        if held == 4 && b == b' ' {
            state.from = 0;
            qp_token(state, b"=46", emit);
            qp_token(state, b"rom", emit);
            state.pending_ws = Some(b' ');
            return;
        }
        if held < 4 && b"From".get(held) == Some(&b) {
            state.from += 1;
            return;
        }
        if held > 0 {
            qp_flush_from(state, emit);
        } else if b == b'.' {
            qp_token(state, b"=2E", emit);
            return;
        }
    }
    match b {
        b' ' | b'\t' => {
            qp_flush_ws(state, false, emit);
            state.pending_ws = Some(b);
            state.mid_line = true;
        }
        33..=60 | 62..=126 => {
            qp_flush_ws(state, false, emit);
            qp_token(state, &[b], emit);
        }
        _ => {
            qp_flush_ws(state, false, emit);
            qp_hex(state, b, emit);
        }
    }
}

pub(crate) fn qp_push(state: &mut QpState, input: &[u8], emit: &mut impl FnMut(&[u8])) {
    for &b in input {
        if state.pending_cr {
            state.pending_cr = false;
            if b == b'\n' {
                qp_line_break(state, emit);
                continue;
            }
            qp_flush_from(state, emit);
            qp_flush_ws(state, false, emit);
            qp_hex(state, b'\r', emit);
        }
        if b == b'\r' {
            state.pending_cr = true;
            continue;
        }
        qp_byte(state, b, emit);
    }
}

pub(crate) fn qp_finish(state: &mut QpState, emit: &mut impl FnMut(&[u8])) {
    if state.pending_cr {
        state.pending_cr = false;
        qp_flush_from(state, emit);
        qp_flush_ws(state, false, emit);
        qp_hex(state, b'\r', emit);
    }
    qp_flush_from(state, emit);
    qp_flush_ws(state, true, emit);
}

/// Encoded length of `text` under [`qp_push`] and [`qp_finish`].
pub(crate) fn qp_encoded_len(text: &[u8]) -> u64 {
    let mut n = 0u64;
    let mut state = QpState::new();
    let mut count = |b: &[u8]| n += b.len() as u64;
    qp_push(&mut state, text, &mut count);
    qp_finish(&mut state, &mut count);
    n
}

#[cfg(test)]
mod tests {
    use alloc::{string::String, vec::Vec};

    use super::*;

    fn b64(input: &[u8]) -> Vec<u8> {
        let mut out = alloc::vec![0u8; base64_encoded_len(input.len() as u64) as usize];
        let n = base64_encode_lines(input, &mut out).unwrap();
        out.truncate(n);
        out
    }

    fn qp(input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut state = QpState::new();
        qp_push(&mut state, input, &mut |b| out.extend_from_slice(b));
        qp_finish(&mut state, &mut |b| out.extend_from_slice(b));
        assert_eq!(out.len() as u64, qp_encoded_len(input));
        out
    }

    fn qp_decode(enc: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < enc.len() {
            match enc[i] {
                b'=' if enc.get(i + 1) == Some(&b'\r') => i += 3,
                b'=' => {
                    let h = core::str::from_utf8(&enc[i + 1..i + 3]).unwrap();
                    out.push(u8::from_str_radix(h, 16).unwrap());
                    i += 3;
                }
                b'\r' => {
                    out.push(b'\n');
                    i += 2;
                }
                b => {
                    out.push(b);
                    i += 1;
                }
            }
        }
        out
    }

    #[test]
    fn test_base64_rfc4648_vectors() {
        assert_eq!(b64(b""), b"");
        assert_eq!(b64(b"f"), b"Zg==");
        assert_eq!(b64(b"fo"), b"Zm8=");
        assert_eq!(b64(b"foo"), b"Zm9v");
        assert_eq!(b64(b"foob"), b"Zm9vYg==");
        assert_eq!(b64(b"fooba"), b"Zm9vYmE=");
        assert_eq!(b64(b"foobar"), b"Zm9vYmFy");
    }

    #[test]
    fn test_base64_lines_are_76_with_crlf_between() {
        for n in [56usize, 57, 58, 114, 115, 1000] {
            let input: Vec<u8> = (0..n).map(|i| (i * 7) as u8).collect();
            let out = b64(&input);
            assert_eq!(out.len() as u64, base64_encoded_len(n as u64));
            let lines: Vec<&[u8]> = out.split(|&b| b == b'\n').collect();
            for (i, l) in lines.iter().enumerate() {
                let l = l.strip_suffix(b"\r").unwrap_or(l);
                if i + 1 < lines.len() {
                    assert_eq!(l.len(), 76);
                } else {
                    assert!(l.len() <= 76 && !l.is_empty());
                }
            }
            assert!(!out.ends_with(b"\r\n"));
        }
    }

    #[test]
    fn test_base64_decode_strict() {
        let mut out = Vec::new();
        base64_decode(b"Zm9vYmFy", &mut out).unwrap();
        assert_eq!(out, b"foobar");
        out.clear();
        base64_decode(b"Zm8=", &mut out).unwrap();
        assert_eq!(out, b"fo");
        out.clear();
        base64_decode(b"", &mut out).unwrap();
        assert!(out.is_empty());
        for bad in [
            &b"Zm8"[..],
            b"Zm=8",
            b"Z===",
            b"Zm9v YmFy",
            b"Zm9=",
            b"Zh==",
            b"=Zm9",
            b"Zm8=Zm8=",
        ] {
            assert!(base64_decode(bad, &mut Vec::new()).is_err(), "{bad:?}");
        }
        let mut enc = Vec::new();
        base64_append(&[0u8, 1, 2, 250, 251, 252, 253], &mut enc);
        let mut back = Vec::new();
        base64_decode(&enc, &mut back).unwrap();
        assert_eq!(back, [0u8, 1, 2, 250, 251, 252, 253]);
    }

    #[test]
    fn test_crc32c_known_vectors() {
        assert_eq!(crc32c(b""), 0);
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
        assert_eq!(crc32c(&[0xffu8; 32]), 0x62A8_AB43);
    }

    #[test]
    fn test_base64_buffer_too_small_refused() {
        let mut out = [0u8; 3];
        assert!(base64_encode_lines(b"abc", &mut out).is_err());
    }

    #[test]
    fn test_base32_lengths_and_alphabet() {
        let mut out = [0u8; 32];
        assert_eq!(base32(&[0u8; 16], &mut out), 26);
        assert_eq!(base32(&[0xff; 20], &mut out), 32);
        assert!(
            out.iter()
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(b))
        );
        let mut o = [0u8; 8];
        let n = base32(b"f", &mut o);
        assert_eq!(&o[..n], b"my");
    }

    #[test]
    fn test_qp_basic_rules() {
        assert_eq!(qp(b"plain text"), b"plain text");
        assert_eq!(qp(b"a=b"), b"a=3Db");
        assert_eq!(qp(b"tail \nnext"), b"tail=20\r\nnext");
        assert_eq!(qp(b"tab\t\r\nx"), b"tab=09\r\nx");
        assert_eq!(qp(b"end "), b"end=20");
        assert_eq!(qp(b".dot\n.\n"), b"=2Edot\r\n=2E\r\n");
        assert_eq!(
            qp(b"From me\nFromage\nFrom"),
            b"=46rom me\r\nFromage\r\nFrom"
        );
        assert_eq!(qp(b"From \n"), b"=46rom=20\r\n");
        assert_eq!(qp("\u{e9}".as_bytes()), b"=C3=A9");
        assert_eq!(qp(b"a\rb"), b"a=0Db");
        assert_eq!(qp(b"a\r"), b"a=0D");
        assert_eq!(qp(b"\x00\x7f"), b"=00=7F");
    }

    #[test]
    fn test_qp_lines_never_exceed_76_and_round_trip() {
        let mut samples: Vec<Vec<u8>> = alloc::vec![
            b"x".repeat(300),
            "\u{e9}".repeat(200).into_bytes(),
            b"word ".repeat(100),
            b"=".repeat(100),
        ];
        let mut s = String::new();
        for i in 0..2000u32 {
            s.push(char::from_u32(32 + (i * 31) % 95).unwrap());
            if i % 97 == 0 {
                s.push('\n');
            }
        }
        samples.push(s.into_bytes());
        for input in samples {
            let enc = qp(&input);
            for line in enc.split(|&b| b == b'\n') {
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                assert!(line.len() <= 76, "{}", line.len());
                assert!(!line.ends_with(b" ") && !line.ends_with(b"\t"));
            }
            let mut want = input.clone();
            want.retain(|&b| b != b'\r');
            assert_eq!(qp_decode(&enc), want);
        }
    }

    #[test]
    fn test_qp_split_at_every_byte_same_output() {
        let input = b"From the start\n.line \t\nmore = text\r\nFrom\n caf\xc3\xa9 ".to_vec();
        let whole = qp(&input);
        for split in 0..=input.len() {
            let mut out = Vec::new();
            let mut state = QpState::new();
            qp_push(&mut state, &input[..split], &mut |b| {
                out.extend_from_slice(b)
            });
            qp_push(&mut state, &input[split..], &mut |b| {
                out.extend_from_slice(b)
            });
            qp_finish(&mut state, &mut |b| out.extend_from_slice(b));
            assert_eq!(out, whole, "split {split}");
        }
    }

    #[test]
    fn test_qp_public_slice_api_and_overflow() {
        let mut state = QpState::new();
        let mut out = [0u8; 4];
        assert!(quoted_printable_encode(b"\xff\xff", &mut out, &mut state).is_err());
        let mut state = QpState::new();
        let mut out = [0u8; 32];
        let n = quoted_printable_encode(b"ab ", &mut out, &mut state).unwrap();
        let m = quoted_printable_finish(&mut out[n..], &mut state).unwrap();
        assert_eq!(&out[..n + m], b"ab=20");
    }
}
