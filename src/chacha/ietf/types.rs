#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::NONCE_LEN;

#[derive(Clone, Default)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
#[repr(transparent)]
pub struct Nonce([u8; NONCE_LEN]);

#[derive(Clone, Default)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
#[repr(transparent)]
pub struct StreamId([u8; NONCE_LEN]);

impl Nonce {
    pub fn into_stream_id(self) -> StreamId {
        StreamId(self.0)
    }

    pub fn as_stream_id(&self) -> &StreamId {
        // SAFETY: Both types have the same [u8; NONCE_LEN] layout
        unsafe { std::mem::transmute::<&Self, &StreamId>(self) }
    }
}

impl StreamId {
    pub fn into_nonce(self) -> Nonce {
        Nonce(self.0)
    }

    pub fn as_nonce(&self) -> &Nonce {
        // SAFETY: Both types have the same [u8; NONCE_LEN] layout
        unsafe { std::mem::transmute::<&Self, &Nonce>(self) }
    }
}

bytes_wrapper_impl!(Nonce, NONCE_LEN);
bytes_wrapper_impl!(StreamId, NONCE_LEN);
