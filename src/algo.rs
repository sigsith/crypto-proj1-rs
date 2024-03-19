pub fn apply_cryptanalysis(
    plaintext_candidates: &[&str],
    ciphertext: &str,
) -> Option<String> {
    let (plaintext_len, ciphertext_len) =
        verify_input(plaintext_candidates, ciphertext).ok()?;
    // Some("passed".to_string())
    None
}

fn verify_input(
    plaintext_candidates: &[&str],
    ciphertext: &str,
) -> Result<(usize, usize), ()> {
    if plaintext_candidates.is_empty() {
        return Err(());
    }
    let first_length = plaintext_candidates[0].len();
    if !plaintext_candidates.iter().all(|s| s.len() == first_length) {
        return Err(());
    }
    if ciphertext.len() < first_length {
        return Err(());
    }
    Ok((first_length, ciphertext.len()))
}
