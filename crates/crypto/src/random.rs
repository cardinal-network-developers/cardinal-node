//! The operating system's random source (`crypto.md#random-numbers`).

/// Fills `buf` from the operating system's cryptographic random source.
///
/// # Panics
///
/// Panics if the OS random source fails. The specification says a device
/// without one cannot participate, so there is nothing sensible to fall
/// back to.
pub fn fill_random(buf: &mut [u8]) {
    getrandom::fill(buf).expect("operating system random source failed");
}

/// Returns `N` random bytes from the operating system.
///
/// # Panics
///
/// As [`fill_random`].
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    fill_random(&mut b);
    b
}
