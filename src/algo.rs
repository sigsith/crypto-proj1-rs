use self::disproof_table::DisproofTable;

pub fn apply_cryptanalysis(
    plaintext_candidates: &[&str],
    ciphertext: &str,
) -> Option<String> {
    // Validate that the plaintexts and the ciphertext are coorectly formatted.
    let (plaintext_len, ciphertext_len) =
        validate_input(plaintext_candidates, ciphertext).ok()?;
    // Try each plaintext-ciphertext pair to see if any matches
    for plaintext in plaintext_candidates {
        if check_plaintext_ciphertext_pair(plaintext, ciphertext) {
            return Some((*plaintext).to_string());
        }
    }
    None
}

// Return whether it is the case that the plaintext is mapped to the ciphertext.
pub fn check_plaintext_ciphertext_pair(
    plaintext: &str,
    ciphertext: &str,
) -> bool {
    // 1. Try each combinations of key-value pair to eliminate impossible pairs
    let mut disproof_table = DisproofTable::new();
    for ciphertext_symbol in 0..27 {
        for plaintext_symbol in 0..27 {}
    }
    false
}

mod disproof_table;

fn validate_input(
    plaintext_candidates: &[&str],
    ciphertext: &str,
) -> Result<(usize, usize), ()> {
    if plaintext_candidates.is_empty() {
        return Err(());
    }
    if !is_lowercase_or_space(ciphertext) {
        return Err(());
    }
    let first_length = plaintext_candidates[0].len();
    if !plaintext_candidates
        .iter()
        .all(|s| s.len() == first_length && is_lowercase_or_space(s))
    {
        return Err(());
    }
    if ciphertext.len() < first_length {
        return Err(());
    }
    Ok((first_length, ciphertext.len()))
}

fn is_lowercase_or_space(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_lowercase() || c == ' ')
}
