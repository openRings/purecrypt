use std::ops::Range;

pub use self::types::{Counter, Nonce};

const NONCE_LEN: usize = 8;
const COUNTER_LEN: usize = 8;

const COUNTER_RANGE: Range<usize> = 12..14;
const NONCE_RANGE: Range<usize> = 14..16;

mod cipher;
mod core;
mod rng;
mod types;

pub type DjbChaCha<const ROUNDS: usize> = cipher::DjbChaCha<ROUNDS>;
pub type DjbChaCha8 = DjbChaCha<8>;
pub type DjbChaCha12 = DjbChaCha<12>;
pub type DjbChaCha20 = DjbChaCha<20>;

pub type DjbChaChaRng<const ROUNDS: usize> = rng::DjbChaChaRng<ROUNDS>;
pub type DjbChaCha8Rng = DjbChaChaRng<8>;
pub type DjbChaCha12Rng = DjbChaChaRng<12>;
pub type DjbChaCha20Rng = DjbChaChaRng<20>;

pub type DjbChaChaCore<const ROUNDS: usize> = core::DjbChaChaCore<ROUNDS>;
pub type DjbChaCha8Core = DjbChaChaCore<8>;
pub type DjbChaCha12Core = DjbChaChaCore<12>;
pub type DjbChaCha20Core = DjbChaChaCore<20>;
