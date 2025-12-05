#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{COUNTER_LEN, COUNTER_RANGE, NONCE_LEN, NONCE_RANGE};
use crate::chacha::consts::*;
use crate::chacha::{column_round, diagonal_round};
use crate::utils::{bytes_to_words, words_to_bytes};

#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct DjbChaChaCore<const ROUNDS: usize>([u32; STATE_LEN_WORDS]);

impl<const ROUNDS: usize> DjbChaChaCore<ROUNDS> {
    #[allow(unused_mut)]
    pub fn new(key: &[u8; KEY_LEN], mut nonce: u64) -> Self {
        let mut state = [0_u32; STATE_LEN_WORDS];

        bytes_to_words(&DEFAULT_CONSTANTS, &mut state[CONSTANTS_RANGE]);
        bytes_to_words(key, &mut state[KEY_RANGE]);
        bytes_to_words(&nonce.to_le_bytes(), &mut state[NONCE_RANGE]);

        #[cfg(feature = "zeroize")]
        nonce.zeroize();

        Self(state)
    }

    pub fn get_state(&self) -> &[u32; STATE_LEN_WORDS] {
        &self.0
    }

    pub fn get_constants(&self) -> &[u32; CONSTANTS_LEN_WORDS] {
        let slice = &self.0[CONSTANTS_RANGE];
        debug_assert_eq!(slice.len(), CONSTANTS_LEN_WORDS);

        // SAFETY: the slice has exactly len properly aligned u32
        unsafe { &*(slice.as_ptr() as *const [u32; CONSTANTS_LEN_WORDS]) }
    }

    pub fn set_constants(&mut self, constants: &[u8; CONSTANTS_LEN]) {
        bytes_to_words(constants, &mut self.0[CONSTANTS_RANGE]);
    }

    pub fn get_key(&self) -> &[u32; KEY_LEN_WORDS] {
        let slice = &self.0[KEY_RANGE];
        debug_assert_eq!(slice.len(), KEY_LEN_WORDS);

        // SAFETY: the slice has exactly len properly aligned u32
        unsafe { &*(slice.as_ptr() as *const [u32; KEY_LEN_WORDS]) }
    }

    pub fn set_key(&mut self, key: &[u8; KEY_LEN]) {
        bytes_to_words(key, &mut self.0[KEY_RANGE]);
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

    #[inline(always)]
    pub fn generate_block(&mut self, dst: &mut [u8]) {
        let mut working = self.0;

        for i in 0..ROUNDS {
            match i % 2 == 0 {
                true => column_round(&mut working),
                false => diagonal_round(&mut working),
            }
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
}
