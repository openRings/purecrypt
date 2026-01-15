use hex_literal::hex;
use purecrypt::chacha::ietf::Nonce as IetfNonce;
use purecrypt::chacha::{ChaCha20, Key};

#[test]
fn ietf_chacha20_block_rfc8439() {
    // RFC 8439 section 2.3.2 test vector:
    // https://www.rfc-editor.org/rfc/rfc8439#section-2.3.2
    let key = Key::new([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ]);
    let nonce = IetfNonce::new([
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ]);

    let mut cipher = ChaCha20::new(&key, &nonce);
    cipher.set_counter(1);

    let mut block = [0u8; 64];
    cipher.apply_keystream(&mut block);

    let expected = hex!(
        "10f1e7e4d13b5915500fdd1fa32071c4
         c7d1f4c733c068030422aa9ac3d46c4e
         d2826446079faa0914c2d705d98b02a2
         b5129cd1de164eb9cbd083e8a2503c4e"
    );

    assert_eq!(block.as_slice(), expected.as_slice());
}

#[test]
fn ietf_chacha20_cipher_rfc8439() {
    // RFC 8439 section 2.4.2 test vector:
    // https://www.rfc-editor.org/rfc/rfc8439#section-2.4.2
    let key = Key::new([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ]);
    let nonce = IetfNonce::new([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ]);

    let mut plaintext = hex!(
        "4c616469657320616e642047656e746c
         656d656e206f662074686520636c6173
         73206f66202739393a20496620492063
         6f756c64206f6666657220796f75206f
         6e6c79206f6e652074697020666f7220
         746865206675747572652c2073756e73
         637265656e20776f756c642062652069
         742e"
    )
    .to_vec();

    let mut cipher = ChaCha20::new(&key, &nonce);
    cipher.set_counter(1);
    cipher.apply_keystream(&mut plaintext);

    let expected = hex!(
        "6e2e359a2568f98041ba0728dd0d6981
         e97e7aec1d4360c20a27afccfd9fae0b
         f91b65c5524733ab8f593dabcd62b357
         1639d624e65152ab8f530c359f0861d8
         07ca0dbf500d6a6156a38e088a22b65e
         52bc514d16ccf806818ce91ab7793736
         5af90bbf74a35be6b40b8eedf2785e42
         874d"
    )
    .to_vec();

    assert_eq!(plaintext, expected);
}
