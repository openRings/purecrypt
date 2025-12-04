#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::COUNTER_LEN;
use super::{COUNTER_RANGE, NONCE_LEN, NONCE_RANGE};
use crate::chacha::full_round;
use crate::chacha::types::Key;
use crate::chacha::{Constants, consts::*};
use crate::utils::{bytes_to_words, words_to_bytes};

#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct DjbChaChaCore<const ROUNDS: usize>([u32; STATE_LEN_WORDS]);

impl<const ROUNDS: usize> DjbChaChaCore<ROUNDS> {
    #[allow(unused_mut)]
    pub fn new(key: &Key, mut nonce: u64) -> Self {
        let mut state = [0_u32; STATE_LEN_WORDS];

        bytes_to_words(&DEFAULT_CONSTANTS, &mut state[CONSTANTS_RANGE]);
        bytes_to_words(key.bytes(), &mut state[KEY_RANGE]);
        bytes_to_words(&nonce.to_le_bytes(), &mut state[NONCE_RANGE]);

        #[cfg(feature = "zeroize")]
        nonce.zeroize();

        Self(state)
    }

    #[inline(always)]
    pub fn generate_block(&mut self, dst: &mut [u8]) {
        let mut working = self.0;

        for _ in 0..(ROUNDS / 2) {
            full_round(&mut working);
        }

        (0..STATE_LEN_WORDS).for_each(|i| {
            working[i] = working[i].wrapping_add(self.0[i]);
        });

        const COUNTER_L: usize = COUNTER_RANGE.start;
        const COUNTER_H: usize = COUNTER_L + 1;

        self.0[COUNTER_L] = self.0[COUNTER_L].wrapping_add(1);

        if self.0[COUNTER_L] == 0 {
            self.0[COUNTER_H] = self.0[COUNTER_H].wrapping_add(1)
        }

        words_to_bytes(&working, dst);

        #[cfg(feature = "zeroize")]
        working.zeroize();
    }

    pub fn get_state(&self) -> &[u32; STATE_LEN_WORDS] {
        &self.0
    }

    pub fn get_key(&self) -> Key {
        let mut key = Key::default();
        words_to_bytes(&self.0[KEY_RANGE], key.bytes_mut());

        key
    }

    pub fn set_key(&mut self, key: &Key) {
        bytes_to_words(key.bytes(), &mut self.0[KEY_RANGE]);
    }

    pub fn get_constants(&self) -> Constants {
        let mut constants = Constants::default();
        words_to_bytes(&self.0[CONSTANTS_RANGE], constants.bytes_mut());

        constants
    }

    pub fn set_constants(&mut self, constants: &Constants) {
        bytes_to_words(constants.bytes(), &mut self.0[CONSTANTS_RANGE]);
    }

    pub fn get_counter(&self) -> u64 {
        let mut buf = [0; COUNTER_LEN];
        words_to_bytes(&self.0[COUNTER_RANGE], &mut buf);

        u64::from_le_bytes(buf)
    }

    pub fn set_counter(&mut self, counter: u64) {
        let bytes = counter.to_le_bytes();

        bytes_to_words(&bytes, &mut self.0[COUNTER_RANGE]);
    }

    pub fn get_nonce(&self) -> u64 {
        let mut buf = [0; NONCE_LEN];
        words_to_bytes(&self.0[NONCE_RANGE], &mut buf);

        u64::from_le_bytes(buf)
    }

    pub fn set_nonce(&mut self, nonce: u64) {
        let bytes = nonce.to_le_bytes();

        bytes_to_words(&bytes, &mut self.0[NONCE_RANGE]);
    }
}
