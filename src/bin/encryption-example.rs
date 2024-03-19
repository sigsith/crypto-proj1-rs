use crypto_proj1_rs::{encryption, plaintext};

fn main() {
    let plaintexts = plaintext::get_hardcoded_plaintexts();
    let mut rng = rand::thread_rng();
    let randomness = 0.2;
    for _ in 0..4 {
        let encrypted =
            encryption::gen_challenge(&plaintexts, randomness, &mut rng);
        println!("{encrypted}")
    }
}
