use hex_literal::hex;
use purecrypt::chacha::Key;
use purecrypt::chacha::djb::{DjbChaCha8, DjbChaCha12, DjbChaCha20, Nonce as DjbNonce};

#[test]
fn djb_chacha_tc1_vectors_draft_strombergson() {
    // IETF draft test vectors (TC1, 256-bit key, 64-bit IV):
    // https://www.ietf.org/archive/id/draft-strombergson-chacha-test-vectors-01.txt
    let key = Key::new([0u8; 32]);
    let nonce = DjbNonce::from_u64(0);

    let expected_8 = hex!(
        "3e00ef2f895f40d67f5bb8e81f09a5a1
         2c840ec3ce9a7f3b181be188ef711a1e
         984ce172b9216f419f445367456d5619
         314a42a3da86b001387bfdb80e0cfe42
         d2aefa0deaa5c151bf0adb6c01f2a5ad
         c0fd581259f9a2aadcf20f8fd566a26b
         5032ec38bbc5da98ee0c6f568b872a65
         a08abf251deb21bb4b56e5d8821e68aa"
    );

    let expected_12 = hex!(
        "9bf49a6a0755f953811fce125f2683d5
         0429c3bb49e074147e0089a52eae155f
         0564f879d27ae3c02ce82834acfa8c79
         3a629f2ca0de6919610be82f411326be
         0bd58841203e74fe86fc71338ce0173d
         c628ebb719bdcbcc151585214cc089b4
         42258dcda14cf111c602b8971b8cc843
         e91e46ca905151c02744a6b017e69316"
    );

    let expected_20 = hex!(
        "76b8e0ada0f13d90405d6ae55386bd28
         bdd219b8a08ded1aa836efcc8b770dc7
         da41597c5157488d7724e03fb8d84a37
         6a43b8f41518a11cc387b669b2ee6586
         9f07e7be5551387a98ba977c732d080d
         cb0f29a048e3656912c6533e32ee7aed
         29b721769ce64e43d57133b074d839d5
         31ed1f28510afb45ace10a1f4b794d6f"
    );

    let mut cipher_8 = DjbChaCha8::new(&key, &nonce);
    let mut out_8 = vec![0u8; expected_8.len()];
    cipher_8.apply_keystream(&mut out_8);
    assert_eq!(out_8.as_slice(), expected_8.as_slice());

    let mut cipher_12 = DjbChaCha12::new(&key, &nonce);
    let mut out_12 = vec![0u8; expected_12.len()];
    cipher_12.apply_keystream(&mut out_12);
    assert_eq!(out_12.as_slice(), expected_12.as_slice());

    let mut cipher_20 = DjbChaCha20::new(&key, &nonce);
    let mut out_20 = vec![0u8; expected_20.len()];
    cipher_20.apply_keystream(&mut out_20);
    assert_eq!(out_20.as_slice(), expected_20.as_slice());
}
