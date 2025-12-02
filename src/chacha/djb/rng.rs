use rand_core::{RngCore, SeedableRng};

use super::NONCE_LEN;
use super::core::DjbChaChaCore;
use crate::chacha::consts::*;

const DEFAULT_STREAM_ID: [u8; NONCE_LEN] = [0; NONCE_LEN];

pub struct DjbChaChaRng<const ROUNDS: usize> {
    core: DjbChaChaCore<ROUNDS>,
    buffer: [u8; OUTPUT_LEN],
    buffer_pos: usize,
}

impl<const ROUNDS: usize> DjbChaChaRng<ROUNDS> {
    pub fn new<K, N>(seed: K, stream_id: N) -> Self
    where
        K: Into<[u8; KEY_LEN]>,
        N: Into<[u8; NONCE_LEN]>,
    {
        let key = seed.into();
        let nonce = stream_id.into();

        let buffer = [0; OUTPUT_LEN];
        let core = DjbChaChaCore::new(key, nonce);
        let buffer_pos = buffer.len();

        Self {
            core,
            buffer,
            buffer_pos,
        }
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
    pub fn get_stream_id(&self) -> u64 {
        self.core.get_nonce()
    }

    #[inline]
    pub fn set_stream_id(&mut self, stream_id: u64) {
        self.core.set_nonce(stream_id);
    }

    #[inline]
    pub fn get_counter(&self) -> u64 {
        self.core.get_counter()
    }

    pub fn set_counter(&mut self, counter: u64) {
        self.core.set_counter(counter);
    }

    #[inline]
    pub fn get_seed(&self) -> [u8; KEY_LEN] {
        self.core.get_key()
    }

    #[inline]
    pub fn set_seed<S>(&mut self, seed: S)
    where
        S: Into<[u8; KEY_LEN]>,
    {
        self.core.set_key(seed.into());
    }

    #[inline]
    pub fn get_constants(&self) -> [u8; CONSTANTS_LEN] {
        self.core.get_constants()
    }

    pub fn set_constants<C>(&mut self, constants: C)
    where
        C: Into<[u8; CONSTANTS_LEN]>,
    {
        self.core.set_constants(constants.into());
    }

    #[inline(always)]
    fn refill(&mut self) {
        self.buffer = self.core.generate_block();
        self.buffer_pos = 0;
    }
}

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

    fn fill_bytes(&mut self, mut dst: &mut [u8]) {
        // use the remaining buffer
        if self.buffer_pos < 64 {
            let take = dst.len().min(64 - self.buffer_pos);
            dst[..take].copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + take]);
            self.buffer_pos += take;
            dst = &mut dst[take..];
        }

        // filling in the main part of the dst
        while dst.len() >= 64 {
            self.refill();
            dst[..64].copy_from_slice(&self.buffer);
            dst = &mut dst[64..];
        }

        // filling in the tail
        if !dst.is_empty() {
            self.refill();
            let n = dst.len();
            dst.copy_from_slice(&self.buffer[..n]);
            self.buffer_pos = n;
        }
    }
}

impl<const ROUNDS: usize> SeedableRng for DjbChaChaRng<ROUNDS> {
    type Seed = [u8; KEY_LEN];

    fn from_seed(seed: Self::Seed) -> Self {
        Self::new(seed, DEFAULT_STREAM_ID)
    }
}
