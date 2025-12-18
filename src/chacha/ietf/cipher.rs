use super::core::IETFChaChaCore;
use super::{ChaChaCore, Nonce};
use crate::chacha::consts::*;
use crate::chacha::{Constants, Key};
use crate::utils::xor_keystream;

pub struct IETFChaCha<const ROUNDS: usize> {
    core: ChaChaCore<ROUNDS>,
    buffer: [u8; OUTPUT_LEN],
    buffer_pos: usize,
}

impl<const ROUNDS: usize> IETFChaCha<ROUNDS> {
    pub fn new(key: &Key, nonce: &Nonce) -> Self {
        let buffer = [0; OUTPUT_LEN];
        let core = IETFChaChaCore::new(key.bytes(), nonce.bytes());
        let buffer_pos = buffer.len();

        Self {
            core,
            buffer,
            buffer_pos,
        }
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
    pub fn get_key(&self) -> &Key {
        Key::from_words_ref(self.core.get_key())
    }

    #[inline]
    pub fn set_key(&mut self, key: &Key) {
        self.core.set_key(key.bytes());
    }

    #[inline]
    pub fn with_key(mut self, key: &Key) -> Self {
        self.set_key(key);

        self
    }

    #[inline]
    pub fn get_counter(&self) -> u32 {
        self.core.get_counter()
    }

    #[inline]
    pub fn set_counter(&mut self, counter: u32) {
        self.core.set_counter(counter);
    }

    #[inline]
    pub fn with_counter(mut self, counter: u32) -> Self {
        self.set_counter(counter);

        self
    }

    #[inline]
    pub fn get_nonce(&self) -> &Nonce {
        Nonce::from_words_ref(self.core.get_nonce())
    }

    #[inline]
    pub fn set_nonce(&mut self, nonce: &Nonce) {
        self.core.set_nonce(nonce.bytes());
    }

    #[inline]
    pub fn with_nonce(mut self, nonce: &Nonce) -> Self {
        self.set_nonce(nonce);

        self
    }

    pub fn apply_keystream(&mut self, mut dst: &mut [u8]) {
        const BLOCK_SIZE: usize = OUTPUT_LEN;

        // apply the remaining buffer
        if self.buffer_pos < BLOCK_SIZE {
            let take = dst.len().min(BLOCK_SIZE - self.buffer_pos);
            xor_keystream(&self.buffer[self.buffer_pos..], &mut dst[..take]);
            self.buffer_pos += take;
            dst = &mut dst[take..];
        }

        let mut key_block = [0; BLOCK_SIZE];

        // applying the main part of the dst
        while dst.len() >= BLOCK_SIZE {
            self.core.generate_block(&mut key_block);
            xor_keystream(&key_block, &mut dst[..BLOCK_SIZE]);
            dst = &mut dst[BLOCK_SIZE..];
        }

        // filling in the tail
        if !dst.is_empty() {
            self.refill();
            let n = dst.len();
            xor_keystream(&self.buffer[..n], dst);
            self.buffer_pos = n;
        }
    }

    #[inline(always)]
    fn refill(&mut self) {
        self.core.generate_block(&mut self.buffer);
        self.buffer_pos = 0;
    }
}
