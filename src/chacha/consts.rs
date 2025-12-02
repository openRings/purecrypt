use std::ops::Range;

pub const CONSTANTS_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
pub const STATE_LEN: usize = 64;
pub const OUTPUT_LEN: usize = 64;
pub const STATE_LEN_WORDS: usize = STATE_LEN / 4;

pub const CONSTANTS_RANGE: Range<usize> = 0..4;
pub const KEY_RANGE: Range<usize> = 4..12;

pub const DEFAULT_CONSTANTS: [u8; CONSTANTS_LEN] = *b"expand 32-byte k";
