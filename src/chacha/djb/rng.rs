#[cfg(feature = "rand")]
use rand_core::{CryptoRng, RngCore, SeedableRng};

use super::core::DjbChaChaCore;
use crate::chacha::types::Seed;
use crate::chacha::{Constants, consts::*};

const DEFAULT_STREAM_ID: u64 = 0;

pub struct DjbChaChaRng<const ROUNDS: usize> {
    core: DjbChaChaCore<ROUNDS>,
    buffer: [u8; OUTPUT_LEN],
    buffer_pos: usize,
}

impl<const ROUNDS: usize> DjbChaChaRng<ROUNDS> {
    pub fn new(seed: &Seed, stream_id: u64) -> Self {
        let buffer = [0; OUTPUT_LEN];
        let core = DjbChaChaCore::new(seed.bytes(), stream_id);
        let buffer_pos = buffer.len();

        Self {
            core,
            buffer,
            buffer_pos,
        }
    }

    #[inline]
    pub fn from_seed(seed: &Seed) -> Self {
        Self::new(seed, DEFAULT_STREAM_ID)
    }

    #[inline]
    pub fn get_core(&self) -> &DjbChaChaCore<ROUNDS> {
        &self.core
    }

    #[inline]
    pub fn get_core_mut(&mut self) -> &mut DjbChaChaCore<ROUNDS> {
        &mut self.core
    }

    #[inline]
    pub fn get_constants(&self) -> &Constants {
        Constants::from_words_ref(self.core.get_constants())
    }

    #[inline]
    pub fn set_constants(&mut self, constants: &Constants) {
        self.core.set_constants(constants.bytes());
    }

    #[inline]
    pub fn with_constants(mut self, constants: &Constants) -> Self {
        self.set_constants(constants);

        self
    }

    #[inline]
    pub fn get_seed(&self) -> &Seed {
        Seed::from_words_ref(self.core.get_key())
    }

    #[inline]
    pub fn set_seed(&mut self, seed: &Seed) {
        self.core.set_key(seed.bytes());
    }

    #[inline]
    pub fn with_seed(mut self, seed: &Seed) -> Self {
        self.set_seed(seed);

        self
    }

    #[inline]
    pub fn get_counter(&self) -> u64 {
        self.core.get_counter()
    }

    #[inline]
    pub fn set_counter(&mut self, counter: u64) {
        self.core.set_counter(counter);
    }

    #[inline]
    pub fn with_counter(mut self, counter: u64) -> Self {
        self.set_counter(counter);

        self
    }

    #[inline]
    pub fn get_stream_id(&self) -> u64 {
        self.core.get_nonce()
    }

    #[inline]
    pub fn set_stream_id(&mut self, stream_id: u64) {
        self.core.set_nonce(stream_id);
    }

    #[inline]
    pub fn with_stream_id(mut self, stream_id: u64) -> Self {
        self.set_stream_id(stream_id);

        self
    }

    pub fn fill_bytes(&mut self, mut dst: &mut [u8]) {
        const BLOCK_SIZE: usize = 64;

        // use the remaining buffer
        if self.buffer_pos < BLOCK_SIZE {
            let take = dst.len().min(BLOCK_SIZE - self.buffer_pos);
            dst[..take].copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + take]);
            self.buffer_pos += take;
            dst = &mut dst[take..];
        }

        // filling in the main part of the dst
        while dst.len() >= BLOCK_SIZE {
            self.core.generate_block(&mut dst[..BLOCK_SIZE]);
            dst = &mut dst[BLOCK_SIZE..];
        }

        // filling in the tail
        if !dst.is_empty() {
            self.refill();
            let n = dst.len();
            dst.copy_from_slice(&self.buffer[..n]);
            self.buffer_pos = n;
        }
    }

    #[inline(always)]
    fn refill(&mut self) {
        self.core.generate_block(&mut self.buffer);
        self.buffer_pos = 0;
    }
}

#[cfg(feature = "rand")]
impl<const ROUNDS: usize> RngCore for DjbChaChaRng<ROUNDS> {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0; (u32::BITS / 8) as usize];
        self.fill_bytes(&mut buf);

        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0; (u64::BITS / 8) as usize];
        self.fill_bytes(&mut buf);

        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.fill_bytes(dst);
    }
}

#[cfg(feature = "rand")]
impl<const ROUNDS: usize> CryptoRng for DjbChaChaRng<ROUNDS> {}

#[cfg(feature = "rand")]
impl<const ROUNDS: usize> SeedableRng for DjbChaChaRng<ROUNDS> {
    type Seed = Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        Self::from_seed(&seed)
    }
}
