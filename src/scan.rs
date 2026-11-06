//! Byte scans eight octets at a time with `u64` arithmetic (SWAR), without
//! `unsafe` code or a third-party crate (PLAN 11.3 item 4).

const ONES: u64 = 0x0101_0101_0101_0101;
const HIGHS: u64 = 0x8080_8080_8080_8080;

/// The high bit of each octet of `x` that is zero is set; the lowest set bit
/// is exact (borrows only reach octets above the first zero one).
const fn zero_octets(x: u64) -> u64 {
    x.wrapping_sub(ONES) & !x & HIGHS
}

/// Octets equal to `b`, as `zero_octets` marks them.
const fn equal_octets(x: u64, b: u8) -> u64 {
    zero_octets(x ^ (ONES * b as u64))
}

/// The index of the first CR or LF in `bytes`.
pub(crate) fn find_line_end(bytes: &[u8]) -> Option<usize> {
    let mut chunks = bytes.chunks_exact(8);
    let mut at = 0usize;
    for chunk in &mut chunks {
        let mut w = [0u8; 8];
        w.copy_from_slice(chunk);
        let x = u64::from_le_bytes(w);
        let hit = equal_octets(x, b'\r') | equal_octets(x, b'\n');
        if hit != 0 {
            return Some(at + (hit.trailing_zeros() / 8) as usize);
        }
        at += 8;
    }
    chunks
        .remainder()
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .map(|i| at + i)
}

/// The index of the first octet at or below SP (0x20) in `bytes`, or its
/// length: spaces, tabs, CR, LF, and the other controls.
pub(crate) fn skip_above_space(bytes: &[u8]) -> usize {
    let mut chunks = bytes.chunks_exact(8);
    let mut at = 0usize;
    for chunk in &mut chunks {
        let mut w = [0u8; 8];
        w.copy_from_slice(chunk);
        let x = u64::from_le_bytes(w);
        // Octets below 0x21; the lowest flag is exact, as in `zero_octets`.
        let hit = x.wrapping_sub(ONES * 0x21) & !x & HIGHS;
        if hit != 0 {
            return at + (hit.trailing_zeros() / 8) as usize;
        }
        at += 8;
    }
    at + chunks
        .remainder()
        .iter()
        .position(|&b| b <= b' ')
        .unwrap_or(chunks.remainder().len())
}

/// True for an octet quoted-printable writes as it is.
pub(crate) const fn qp_literal(b: u8) -> bool {
    matches!(b, 33..=60 | 62..=126)
}

/// True when every octet of `bytes` is printable ASCII (0x20 to 0x7e) or TAB.
pub(crate) fn is_printable_or_tab(bytes: &[u8]) -> bool {
    let plain = |b: &u8| *b == b'\t' || (0x20..0x7f).contains(b);
    let mut chunks = bytes.chunks_exact(8);
    for chunk in &mut chunks {
        let mut w = [0u8; 8];
        w.copy_from_slice(chunk);
        let x = u64::from_le_bytes(w);
        let low = x.wrapping_sub(ONES * 0x20) & !x & HIGHS;
        let high = (x | x.wrapping_add(ONES)) & HIGHS;
        // A flag may be a TAB or a borrow from one: check those octets.
        if (low | high) != 0 && !chunk.iter().all(plain) {
            return false;
        }
    }
    chunks.remainder().iter().all(plain)
}

/// True when every octet of `bytes` is ASCII.
pub(crate) fn is_ascii(bytes: &[u8]) -> bool {
    let mut chunks = bytes.chunks_exact(8);
    for chunk in &mut chunks {
        let mut w = [0u8; 8];
        w.copy_from_slice(chunk);
        if u64::from_le_bytes(w) & HIGHS != 0 {
            return false;
        }
    }
    chunks.remainder().is_ascii()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scans_match_the_plain_loop_at_every_offset() {
        let mut sample = alloc::vec::Vec::new();
        for b in 0..=255u8 {
            sample.extend_from_slice(b"abcdefghij");
            sample.push(b);
        }
        for start in 0..sample.len() {
            for len in [0, 1, 7, 8, 9, 15, 16, 17, 40] {
                let s = sample.get(start..(start + len).min(sample.len())).unwrap();
                assert_eq!(
                    find_line_end(s),
                    s.iter().position(|&b| b == b'\r' || b == b'\n'),
                    "{s:?}"
                );
                assert_eq!(is_ascii(s), s.is_ascii());
                assert_eq!(
                    skip_above_space(s),
                    s.iter().position(|&b| b <= b' ').unwrap_or(s.len()),
                    "{s:?}"
                );
                assert_eq!(
                    is_printable_or_tab(s),
                    s.iter().all(|&b| b == b'\t' || (0x20..0x7f).contains(&b)),
                    "{s:?}"
                );
            }
        }
    }
}
