#[inline(always)]
pub(crate) fn bytes_to_words(src: &[u8], dest: &mut [u32]) {
    for (i, chunk) in src.chunks_exact(4).enumerate() {
        dest[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
}

#[inline(always)]
pub(crate) fn words_to_bytes(src: &[u32], dest: &mut [u8]) {
    for (i, &w) in src.iter().enumerate() {
        let b = w.to_le_bytes();
        dest[i * 4] = b[0];
        dest[i * 4 + 1] = b[1];
        dest[i * 4 + 2] = b[2];
        dest[i * 4 + 3] = b[3];
    }
}

#[inline(always)]
#[allow(dead_code)]
pub(crate) const fn bytes4_to_word(bytes: [u8; 4]) -> u32 {
    (bytes[0] as u32)
        | ((bytes[1] as u32) << 8)
        | ((bytes[2] as u32) << 16)
        | ((bytes[3] as u32) << 24)
}

#[macro_export]
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
