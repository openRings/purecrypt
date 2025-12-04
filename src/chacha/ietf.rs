use std::ops::Range;

pub use self::types::{Nonce, StreamId};

const NONCE_LEN: usize = 12;
#[allow(dead_code)]
const COUNTER_LEN: usize = 4;

const COUNTER_RANGE: Range<usize> = 12..13;
const NONCE_RANGE: Range<usize> = 13..16;

mod core;
mod rng;
mod types;

pub type ChaChaRng<const ROUNDS: usize> = rng::IETFChaChaRng<ROUNDS>;
pub type ChaCha8Rng = ChaChaRng<8>;
pub type ChaCha12Rng = ChaChaRng<12>;
pub type ChaCha20Rng = ChaChaRng<20>;

pub type ChaChaCore<const ROUNDS: usize> = core::IETFChaChaCore<ROUNDS>;
pub type ChaCha8Core = ChaChaCore<8>;
pub type ChaCha12Core = ChaChaCore<12>;
pub type ChaCha20Core = ChaChaCore<20>;
