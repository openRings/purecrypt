use purecrypt::chacha::ChaCha20Rng;

fn main() {
    let mut buf = vec![0_u8; 1024 * 1024 * 1024];
    let mut rng = ChaCha20Rng::from_seed(&Default::default());

    let now = std::time::Instant::now();

    rng.fill_bytes(&mut buf);

    let elapsed = now.elapsed();

    println!(
        "elasped: {elapsed:?}, \nfirst bytes: {:?}, \nlast bytes: {:?}",
        &buf[0..8],
        &buf[buf.len() - 8..buf.len()]
    );
}
