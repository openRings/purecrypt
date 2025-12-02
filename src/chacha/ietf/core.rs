use super::{COUNTER_RANGE, NONCE_LEN, NONCE_RANGE};
use crate::chacha::consts::*;
use crate::chacha::full_round;
use crate::utils::{bytes_to_words, words_to_bytes};

pub struct IETFChaChaCore<const ROUNDS: usize>([u32; STATE_LEN_WORDS]);

impl<const ROUNDS: usize> IETFChaChaCore<ROUNDS> {
    pub fn new(key: [u8; KEY_LEN], nonce: [u8; NONCE_LEN]) -> Self {
        let mut state = [0_u32; STATE_LEN_WORDS];

        bytes_to_words(&DEFAULT_CONSTANTS, &mut state[CONSTANTS_RANGE]);
        bytes_to_words(&key, &mut state[KEY_RANGE]);
        bytes_to_words(&nonce, &mut state[NONCE_RANGE]);

        Self(state)
    }

    #[inline(always)]
    pub fn get_block(&mut self) -> [u8; STATE_LEN] {
        let mut working = self.0;

        for _ in 0..(ROUNDS / 2) {
            full_round(&mut working);
        }

        (0..STATE_LEN_WORDS).for_each(|i| {
            working[i] = working[i].wrapping_add(self.0[i]);
        });

        self.0[COUNTER_RANGE.start] = self.0[COUNTER_RANGE.start].wrapping_add(1);

        // SAFETY: The arrays have identical size, and `[u8]` has compatible (smaller) alignment.
        unsafe { core::mem::transmute::<[u32; STATE_LEN_WORDS], [u8; STATE_LEN]>(working) }
    }

    pub fn get_key(&self) -> [u8; KEY_LEN] {
        let mut key = [0; KEY_LEN];
        words_to_bytes(&self.0[KEY_RANGE], &mut key);

        key
    }

    pub fn set_key(&mut self, key: [u8; KEY_LEN]) {
        bytes_to_words(&key, &mut self.0[KEY_RANGE]);
    }

    pub fn get_constants(&self) -> [u8; CONSTANTS_LEN] {
        let mut constants = [0; CONSTANTS_LEN];
        words_to_bytes(&self.0[CONSTANTS_RANGE], &mut constants);

        constants
    }

    pub fn set_constants(&mut self, constants: [u8; CONSTANTS_LEN]) {
        bytes_to_words(&constants, &mut self.0[CONSTANTS_RANGE]);
    }

    pub fn get_counter(&self) -> u32 {
        self.0[COUNTER_RANGE.start]
    }

    pub fn set_counter(&mut self, value: u32) {
        self.0[COUNTER_RANGE.start] = value
    }

    pub fn get_nonce(&self) -> [u8; NONCE_LEN] {
        let mut nonce = [0; NONCE_LEN];
        words_to_bytes(&self.0[NONCE_RANGE], &mut nonce);

        nonce
    }

    pub fn set_nonce(&mut self, nonce: [u8; NONCE_LEN]) {
        bytes_to_words(&nonce, &mut self.0[NONCE_RANGE]);
    }
}
