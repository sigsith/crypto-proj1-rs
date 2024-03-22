use crypto_proj1_rs::{algo, plaintext};
use std::io;

fn main() -> Result<(), io::Error> {
    println!("Enter the ciphertext:");
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let ciphertext = input.trim_end_matches('\n');
    let plaintext_candidates = plaintext::get_hardcoded_plaintexts();
    let guess = algo::apply_cryptanalysis(&plaintext_candidates, ciphertext);
    println!("My plaintext guess is:{}", plaintext_candidates[guess]);
    Ok(())
}
