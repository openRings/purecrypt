use purecrypt::chacha::djb::{DjbChaCha20, Nonce as DjbNonce};
use purecrypt::chacha::ietf::{Nonce as IetfNonce, StreamId};
use purecrypt::chacha::{ChaCha8, ChaCha12, ChaCha20, ChaCha20Rng, DjbChaCha20Rng, Key, Seed};

fn apply_in_chunks<F>(mut apply: F, data: &mut [u8])
where
    F: FnMut(&mut [u8]),
{
    let mut offset = 0;
    let sizes = [1_usize, 63, 64, 7, 65, 2, 32, 33];
    let mut i = 0;

    while offset < data.len() {
        let size = sizes[i % sizes.len()].min(data.len() - offset);
        apply(&mut data[offset..offset + size]);
        offset += size;
        i += 1;
    }
}

#[test]
fn ietf_chacha8_chunking_roundtrip() {
    let key = Key::new([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
        0x32, 0x10,
    ]);
    let nonce = IetfNonce::new([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    ]);

    let plaintext = b"The quick brown fox jumps over the lazy dog. ChaCha8 buffer test.";

    let mut one_shot = plaintext.to_vec();
    let mut cipher = ChaCha8::new(&key, &nonce);
    cipher.set_counter(7);
    cipher.apply_keystream(&mut one_shot);

    let mut chunked = plaintext.to_vec();
    let mut cipher_chunked = ChaCha8::new(&key, &nonce);
    cipher_chunked.set_counter(7);
    apply_in_chunks(|chunk| cipher_chunked.apply_keystream(chunk), &mut chunked);

    assert_eq!(one_shot, chunked);

    let mut decrypted = one_shot.clone();
    let mut cipher_decrypt = ChaCha8::new(&key, &nonce);
    cipher_decrypt.set_counter(7);
    cipher_decrypt.apply_keystream(&mut decrypted);
    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn ietf_chacha12_chunking_roundtrip() {
    let key = Key::new([
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45,
        0x23, 0x01,
    ]);
    let nonce = IetfNonce::new([
        0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
    ]);

    let mut plaintext = vec![0u8; 200];
    for (i, byte) in plaintext.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(3);
    }

    let mut one_shot = plaintext.clone();
    let mut cipher = ChaCha12::new(&key, &nonce);
    cipher.set_counter(9);
    cipher.apply_keystream(&mut one_shot);

    let mut chunked = plaintext.clone();
    let mut cipher_chunked = ChaCha12::new(&key, &nonce);
    cipher_chunked.set_counter(9);
    apply_in_chunks(|chunk| cipher_chunked.apply_keystream(chunk), &mut chunked);

    assert_eq!(one_shot, chunked);

    let mut decrypted = one_shot.clone();
    let mut cipher_decrypt = ChaCha12::new(&key, &nonce);
    cipher_decrypt.set_counter(9);
    cipher_decrypt.apply_keystream(&mut decrypted);
    assert_eq!(decrypted, plaintext);
}

#[test]
fn ietf_rng_matches_cipher_keystream() {
    let seed = Seed::new([0u8; 32]);
    let stream_id = StreamId::new([0u8; 12]);

    let mut rng = ChaCha20Rng::new(&seed, &stream_id);
    rng.set_counter(3);
    let mut rng_out = vec![0u8; 128];
    rng.fill_bytes(&mut rng_out);

    let key = Key::new([0u8; 32]);
    let nonce = IetfNonce::new([0u8; 12]);
    let mut cipher = ChaCha20::new(&key, &nonce);
    cipher.set_counter(3);
    let mut cipher_out = vec![0u8; 128];
    cipher.apply_keystream(&mut cipher_out);

    assert_eq!(rng_out, cipher_out);
}

#[test]
fn djb_rng_matches_cipher_keystream() {
    let seed = Seed::new([0u8; 32]);
    let mut rng = DjbChaCha20Rng::new(&seed, 0);
    rng.set_counter(5);
    let mut rng_out = vec![0u8; 128];
    rng.fill_bytes(&mut rng_out);

    let key = Key::new([0u8; 32]);
    let nonce = DjbNonce::from_u64(0);
    let mut cipher = DjbChaCha20::new(&key, &nonce);
    cipher.set_counter(5);
    let mut cipher_out = vec![0u8; 128];
    cipher.apply_keystream(&mut cipher_out);

    assert_eq!(rng_out, cipher_out);
}

#[test]
fn ietf_counter_wraps_u32() {
    let key = Key::new([0u8; 32]);
    let nonce = IetfNonce::new([0u8; 12]);
    let mut cipher = ChaCha20::new(&key, &nonce);

    cipher.set_counter(u32::MAX);
    let mut block = [0u8; 64];
    cipher.apply_keystream(&mut block);

    assert_eq!(cipher.get_counter(), 0);
}

#[test]
fn djb_counter_carries_to_high_word() {
    let key = Key::new([0u8; 32]);
    let nonce = DjbNonce::from_u64(0);
    let mut cipher = DjbChaCha20::new(&key, &nonce);

    cipher.set_counter(u64::from(u32::MAX));
    let mut block = [0u8; 64];
    cipher.apply_keystream(&mut block);

    assert_eq!(cipher.get_counter(), u64::from(u32::MAX) + 1);
}

#[test]
fn djb_counter_wraps_u64() {
    let key = Key::new([0u8; 32]);
    let nonce = DjbNonce::from_u64(0);
    let mut cipher = DjbChaCha20::new(&key, &nonce);

    cipher.set_counter(u64::MAX);
    let mut block = [0u8; 64];
    cipher.apply_keystream(&mut block);

    assert_eq!(cipher.get_counter(), 0);
}
