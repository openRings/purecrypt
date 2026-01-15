use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use purecrypt::chacha::ietf::Nonce as IetfNonce;
use purecrypt::chacha::{ChaCha20, Key};

fn ref_chacha20_bytes(key: [u8; 32], nonce: [u8; 12], counter: u32, len: usize) -> Vec<u8> {
    let mut cipher = chacha20::ChaCha20::new(&key.into(), &nonce.into());
    let offset = u64::from(counter) * 64;
    cipher.seek(offset);

    let mut out = vec![0u8; len];
    cipher.apply_keystream(&mut out);
    out
}

#[test]
fn ietf_matches_rustcrypto_counters() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let counters = [0u32, 1, 2, 7, u32::MAX - 1];

    for &counter in &counters {
        let mut ours = vec![0u8; 64];
        let mut cipher = ChaCha20::new(&Key::new(key), &IetfNonce::new(nonce));
        cipher.set_counter(counter);
        cipher.apply_keystream(&mut ours);

        let reference = ref_chacha20_bytes(key, nonce, counter, 64);
        assert_eq!(ours, reference);
    }
}

#[test]
fn ietf_matches_rustcrypto_unaligned_offset() {
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 12];

    let mut ours = vec![0u8; 7 + 64];
    let mut cipher = ChaCha20::new(&Key::new(key), &IetfNonce::new(nonce));
    cipher.apply_keystream(&mut ours);

    let mut reference = vec![0u8; 64];
    let mut ref_cipher = chacha20::ChaCha20::new(&key.into(), &nonce.into());
    ref_cipher.seek(7);
    ref_cipher.apply_keystream(&mut reference);

    assert_eq!(ours[7..], reference);
}
