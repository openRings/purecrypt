#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::consts::*;

#[derive(Clone)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
#[repr(transparent)]
pub struct Constants([u8; CONSTANTS_LEN]);

#[derive(Clone, Default)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
#[repr(transparent)]
pub struct Key([u8; KEY_LEN]);

#[derive(Clone, Default)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
#[repr(transparent)]
pub struct Seed([u8; KEY_LEN]);

impl Constants {
    pub fn is_default(&self) -> bool {
        self.0 == DEFAULT_CONSTANTS
    }
}

impl Key {
    pub fn into_seed(self) -> Seed {
        Seed(self.0)
    }

    pub fn as_seed(&self) -> &Seed {
        // SAFETY: Both types have the same [u8; KEY_LEN] layout
        unsafe { std::mem::transmute::<&Self, &Seed>(self) }
    }
}

impl Seed {
    pub fn into_key(&self) -> Key {
        Key(self.0)
    }

    pub fn as_key(&self) -> &Key {
        // SAFETY: Both types have the same [u8; KEY_LEN] layout
        unsafe { std::mem::transmute::<&Self, &Key>(self) }
    }
}

impl Default for Constants {
    fn default() -> Self {
        Self::new(DEFAULT_CONSTANTS)
    }
}

bytes_wrapper_impl!(Constants, CONSTANTS_LEN);
bytes_wrapper_impl!(Key, KEY_LEN);
bytes_wrapper_impl!(Seed, KEY_LEN);
