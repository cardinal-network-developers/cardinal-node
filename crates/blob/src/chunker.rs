//! FastCDC normalized chunking with the fixed parameters of
//! `blobs.md#chunking`.
//!
//! The rolling hash is `h = (h << 1) + gear[byte]` modulo 2^64, so after
//! processing byte `p`, `h` is the sum of `gear[byte[q]] << (p - q)` over
//! the bytes `q` of the chunk so far, and every term with `p - q >= 64` has
//! been shifted out. The first boundary test happens at `n = min`, so the
//! bytes before `min - 64` can never influence a decision and are not
//! hashed. The result is identical to the specification's loop.

use std::sync::OnceLock;

/// Minimum chunk size: 16 KiB.
pub const MIN_SIZE: usize = 16 * 1024;
/// Target average chunk size: 64 KiB.
pub const AVG_SIZE: usize = 64 * 1024;
/// Maximum chunk size: 256 KiB.
pub const MAX_SIZE: usize = 256 * 1024;

/// The top 18 bits of a 64-bit word: used below the average size.
pub const MASK_HARD: u64 = !0u64 << (64 - 18);
/// The top 14 bits of a 64-bit word: used at and above the average size.
pub const MASK_EASY: u64 = !0u64 << (64 - 14);

/// The gear table: `gear[i]` is the first 8 bytes, little-endian, of
/// `BLAKE3("cardinal 1 gear" || byte(i))`, for every byte value `i`.
pub fn gear() -> &'static [u64; 256] {
    static GEAR: OnceLock<[u64; 256]> = OnceLock::new();
    GEAR.get_or_init(|| {
        let mut t = [0u64; 256];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut h = blake3::Hasher::new();
            h.update(b"cardinal 1 gear");
            h.update(&[i as u8]);
            let out = h.finalize();
            *slot = u64::from_le_bytes(out.as_bytes()[..8].try_into().unwrap());
        }
        t
    })
}

/// The length of the chunk that starts at `data[0]`, where `data` ends
/// where the content ends or extends at least [`MAX_SIZE`] bytes.
///
/// Returns `data.len()` if no boundary is found before the end, so the
/// caller must pass at least `MAX_SIZE` bytes unless `data` reaches the end
/// of the content.
pub fn cut(data: &[u8]) -> usize {
    let len = data.len();
    if len <= MIN_SIZE {
        return len;
    }
    let g = gear();
    let mut h: u64 = 0;
    // Warm up: bytes that can still be present in h at n = min.
    for &b in &data[MIN_SIZE - 64..MIN_SIZE - 1] {
        h = (h << 1).wrapping_add(g[b as usize]);
    }
    // n in [min, avg): hard mask. Byte index p = n - 1.
    let end_hard = len.min(AVG_SIZE - 1);
    for (p, &b) in data.iter().enumerate().take(end_hard).skip(MIN_SIZE - 1) {
        h = (h << 1).wrapping_add(g[b as usize]);
        if h & MASK_HARD == 0 {
            return p + 1;
        }
    }
    if len < AVG_SIZE {
        return len;
    }
    // n in [avg, max]: easy mask, and n == max always cuts.
    let end_easy = len.min(MAX_SIZE);
    for (p, &b) in data.iter().enumerate().take(end_easy).skip(AVG_SIZE - 1) {
        h = (h << 1).wrapping_add(g[b as usize]);
        if h & MASK_EASY == 0 {
            return p + 1;
        }
    }
    end_easy
}

/// The end offsets of every chunk of `data`, in order. The last is
/// `data.len()`. Empty content has no chunks.
pub fn chunk_boundaries(data: &[u8]) -> Vec<usize> {
    let mut out = Vec::with_capacity(data.len() / AVG_SIZE + 1);
    let mut s = 0;
    while s < data.len() {
        let end = (s + MAX_SIZE).min(data.len());
        s += cut(&data[s..end]);
        out.push(s);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The specification's loop, transcribed literally.
    fn cut_reference(data: &[u8], s: usize) -> usize {
        let g = gear();
        let mut h: u64 = 0;
        let mut p = s;
        while p < data.len() {
            h = (h << 1).wrapping_add(g[data[p] as usize]);
            let n = p - s + 1;
            if n < MIN_SIZE {
                p += 1;
                continue;
            }
            if n == MAX_SIZE {
                return p + 1;
            }
            let mask = if n < AVG_SIZE { MASK_HARD } else { MASK_EASY };
            if h & mask == 0 {
                return p + 1;
            }
            p += 1;
        }
        data.len()
    }

    fn pseudo(n: usize, seed: u8) -> Vec<u8> {
        let mut out = vec![0u8; n];
        let mut h = blake3::Hasher::new();
        h.update(&[seed]);
        h.finalize_xof().fill(&mut out);
        out
    }

    #[test]
    fn matches_reference_loop() {
        for (n, seed) in [(3_000_000, 1u8), (777_777, 2), (16 * 1024 + 1, 3)] {
            let data = pseudo(n, seed);
            let fast = chunk_boundaries(&data);
            let mut slow = Vec::new();
            let mut s = 0;
            while s < data.len() {
                s = cut_reference(&data, s);
                slow.push(s);
            }
            assert_eq!(fast, slow);
        }
    }

    #[test]
    fn low_entropy_hits_max() {
        // A constant input never satisfies a mask (h becomes a fixed point
        // that is not zero in the top bits for this table) or does so
        // reproducibly; either way sizes stay within bounds.
        let data = vec![0u8; 1_000_000];
        let b = chunk_boundaries(&data);
        let mut prev = 0;
        for &e in &b {
            let n = e - prev;
            assert!(n <= MAX_SIZE);
            assert!(n >= MIN_SIZE || e == data.len());
            prev = e;
        }
    }

    #[test]
    fn small_inputs() {
        assert!(chunk_boundaries(&[]).is_empty());
        assert_eq!(chunk_boundaries(&[1, 2, 3]), vec![3]);
        let d = pseudo(MIN_SIZE, 9);
        assert_eq!(chunk_boundaries(&d), vec![MIN_SIZE]);
    }
}
