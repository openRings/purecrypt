#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::NONCE_LEN;

#[derive(Clone, Default)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct Nonce([u8; NONCE_LEN]);

#[derive(Clone, Default)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct StreamId([u8; NONCE_LEN]);

impl Nonce {
    pub fn new<B>(bytes: B) -> Self
    where
        B: Into<[u8; NONCE_LEN]>,
    {
        Self(bytes.into())
    }

    pub fn bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }

    pub fn bytes_mut(&mut self) -> &mut [u8; NONCE_LEN] {
        &mut self.0
    }

    pub fn into_stream_id(self) -> StreamId {
        StreamId(self.0)
    }
}

impl StreamId {
    pub fn new<B>(bytes: B) -> Self
    where
        B: Into<[u8; NONCE_LEN]>,
    {
        Self(bytes.into())
    }

    pub fn bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }

    pub fn bytes_mut(&mut self) -> &mut [u8; NONCE_LEN] {
        &mut self.0
    }

    pub fn into_nonce(self) -> Nonce {
        Nonce(self.0)
    }
}
