#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{COUNTER_LEN, NONCE_LEN};

#[derive(Clone, Default)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
#[repr(transparent)]
pub struct Nonce([u8; NONCE_LEN]);

#[derive(Clone, Default)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
#[repr(transparent)]
pub struct Counter([u8; COUNTER_LEN]);

impl Nonce {
    pub fn from_u64(value: u64) -> Self {
        Self(value.to_le_bytes())
    }

    pub fn as_u64(&self) -> u64 {
        u64::from_le_bytes(*self.bytes())
    }
}

impl Counter {
    pub fn from_u64(value: u64) -> Self {
        Self(value.to_le_bytes())
    }

    pub fn as_u64(&self) -> u64 {
        u64::from_le_bytes(*self.bytes())
    }
}

bytes_wrapper_impl!(Nonce, NONCE_LEN);
bytes_wrapper_impl!(Counter, COUNTER_LEN);
