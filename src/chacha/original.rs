use crate::chacha::consts::*;

#[allow(dead_code)]
pub struct OriginalChaCha<const ROUNDS: usize>([u32; STATE_LEN_WORDS]);
