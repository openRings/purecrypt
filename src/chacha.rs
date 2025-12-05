use std::ops::BitXor;

use self::consts::*;

pub use self::djb::{DjbChaCha8Rng, DjbChaCha12Rng, DjbChaCha20Rng, DjbChaChaRng};
pub use self::ietf::{ChaCha8Rng, ChaCha12Rng, ChaCha20Rng, ChaChaRng};
pub use self::types::{Constants, Key, Seed};

pub mod djb; // DJB original: 64-bit counter, 64-bit nonce
pub mod ietf; // RFC 8439 version: 32-bit counter, 96-bit nonce
mod types;

pub(crate) mod consts;

#[inline(always)]
pub(crate) fn quarter_round(
    state: &mut [u32; STATE_LEN_WORDS],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
) {
    // a += b; d ^= a; d <<<= 16
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = state[d].bitxor(state[a]);
    state[d] = state[d].rotate_left(16);

    // c += d; b ^= c; b <<<= 12
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = state[b].bitxor(state[c]);
    state[b] = state[b].rotate_left(12);

    // a += b; d ^= a; d <<<= 8
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = state[d].bitxor(state[a]);
    state[d] = state[d].rotate_left(8);

    // c += d; b ^= c; b <<<= 7
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = state[b].bitxor(state[c]);
    state[b] = state[b].rotate_left(7);
}

#[inline(always)]
pub(crate) fn column_round(state: &mut [u32; STATE_LEN_WORDS]) {
    quarter_round(state, 0, 4, 8, 12);
    quarter_round(state, 1, 5, 9, 13);
    quarter_round(state, 2, 6, 10, 14);
    quarter_round(state, 3, 7, 11, 15);
}

#[inline(always)]
pub(crate) fn diagonal_round(state: &mut [u32; STATE_LEN_WORDS]) {
    quarter_round(state, 0, 5, 10, 15);
    quarter_round(state, 1, 6, 11, 12);
    quarter_round(state, 2, 7, 8, 13);
    quarter_round(state, 3, 4, 9, 14);
}
