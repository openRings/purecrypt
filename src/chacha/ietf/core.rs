#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::Nonce;
use super::{COUNTER_RANGE, NONCE_RANGE};
use crate::chacha::Constants;
use crate::chacha::Key;
use crate::chacha::consts::*;
use crate::chacha::full_round;
use crate::utils::{bytes_to_words, words_to_bytes};

#[derive(Clone)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct IETFChaChaCore<const ROUNDS: usize>([u32; STATE_LEN_WORDS]);

impl<const ROUNDS: usize> IETFChaChaCore<ROUNDS> {
    pub fn new(key: &Key, nonce: &Nonce) -> Self {
        let mut state = [0_u32; STATE_LEN_WORDS];

        bytes_to_words(&DEFAULT_CONSTANTS, &mut state[CONSTANTS_RANGE]);
        bytes_to_words(key.bytes(), &mut state[KEY_RANGE]);
        bytes_to_words(nonce.bytes(), &mut state[NONCE_RANGE]);

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

        self.0[COUNTER_RANGE.start] = self.0[COUNTER_RANGE.start].wrapping_add(1);

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

    pub fn set_key(&mut self, key: [u8; KEY_LEN]) {
        bytes_to_words(&key, &mut self.0[KEY_RANGE]);
    }

    pub fn get_constants(&self) -> Constants {
        let mut constants = Constants::default();
        words_to_bytes(&self.0[CONSTANTS_RANGE], constants.bytes_mut());

        constants
    }

    pub fn set_constants(&mut self, constants: &Constants) {
        bytes_to_words(constants.bytes(), &mut self.0[CONSTANTS_RANGE]);
    }

    pub fn get_counter(&self) -> u32 {
        self.0[COUNTER_RANGE.start]
    }

    pub fn set_counter(&mut self, value: u32) {
        self.0[COUNTER_RANGE.start] = value
    }

    pub fn get_nonce(&self) -> Nonce {
        let mut nonce = Nonce::default();
        words_to_bytes(&self.0[NONCE_RANGE], nonce.bytes_mut());

        nonce
    }

    pub fn set_nonce(&mut self, nonce: &Nonce) {
        bytes_to_words(nonce.bytes(), &mut self.0[NONCE_RANGE]);
    }
}
