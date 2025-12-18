#[inline(always)]
pub(crate) fn bytes_to_words(src: &[u8], dst: &mut [u32]) {
    for (i, chunk) in src.chunks_exact(4).enumerate() {
        dst[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
}

#[inline(always)]
pub(crate) fn words_to_bytes(src: &[u32], dst: &mut [u8]) {
    #[cfg(target_endian = "little")]
    {
        let bytes = unsafe { std::slice::from_raw_parts(src.as_ptr() as *const u8, src.len() * 4) };
        dst.copy_from_slice(bytes);
    }

    #[cfg(target_endian = "big")]
    {
        for (i, &word) in src.iter().enumerate() {
            dst[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
    }
}

#[inline(always)]
pub(crate) fn xor_keystream(key: &[u8], dst: &mut [u8]) {
    dst.iter_mut().zip(key).for_each(|(d, k)| *d ^= *k);
}

#[inline(always)]
#[allow(dead_code)]
pub(crate) const fn bytes4_to_word(bytes: [u8; 4]) -> u32 {
    (bytes[0] as u32)
        | ((bytes[1] as u32) << 8)
        | ((bytes[2] as u32) << 16)
        | ((bytes[3] as u32) << 24)
}

macro_rules! generate_bytes_to_words {
    ($fn_name:ident, $words:expr) => {
        #[inline(always)]
        pub const fn $fn_name(bytes: [u8; $words * 4]) -> [u32; $words] {
            let mut out = [0u32; $words];
            let mut i = 0;
            while i < $words {
                out[i] = $crate::utils::bytes4_to_word([
                    bytes[i * 4 + 0],
                    bytes[i * 4 + 1],
                    bytes[i * 4 + 2],
                    bytes[i * 4 + 3],
                ]);
                i += 1;
            }
            out
        }
    };
}

generate_bytes_to_words!(bytes8_to_words2, 2);
generate_bytes_to_words!(bytes12_to_words3, 3);
generate_bytes_to_words!(bytes16_to_words4, 4);
generate_bytes_to_words!(bytes32_to_words8, 8);

macro_rules! bytes_wrapper_impl {
    ($struct_name:ident, $len:ident) => {
        impl $struct_name {
            pub const fn new(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            pub const fn new_ref(bytes: &[u8; $len]) -> &Self {
                // SAFETY: Self shares the exact layout with [u8; $len]
                unsafe { std::mem::transmute::<&[u8; $len], &Self>(bytes) }
            }

            pub const fn from_words_ref(words: &[u32; $len / 4]) -> &Self {
                const _: () = assert!($len % 4 == 0);

                // SAFETY: Self shares the exact layout with [u8; $len]
                unsafe { std::mem::transmute::<&[u32; $len / 4], &Self>(words) }
            }

            pub const fn bytes(&self) -> &[u8; $len] {
                &self.0
            }

            pub const fn bytes_mut(&mut self) -> &mut [u8; $len] {
                &mut self.0
            }
        }

        impl From<[u8; $len]> for $struct_name {
            fn from(value: [u8; $len]) -> Self {
                Self(value)
            }
        }

        impl AsRef<[u8]> for $struct_name {
            fn as_ref(&self) -> &[u8] {
                self.bytes()
            }
        }

        impl AsMut<[u8]> for $struct_name {
            fn as_mut(&mut self) -> &mut [u8] {
                self.bytes_mut()
            }
        }
    };
}
