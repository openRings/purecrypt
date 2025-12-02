use std::ops::Range;

pub use self::rng::IETFChaChaRng;

const NONCE_LEN: usize = 12;
#[allow(dead_code)]
const COUNTER_LEN: usize = 1;

const COUNTER_RANGE: Range<usize> = 12..13;
const NONCE_RANGE: Range<usize> = 13..16;

mod rng;

pub mod core;
