mod disproof_stats;
mod disproof_table;

use self::disproof_table::DisproofTable;
use crate::{
    algo::disproof_stats::DisproofStatsCollector, encryption::string_to_vec,
};

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
    // 0. Convert plaintext and ciphertext to integer representations.
    let plaintext = string_to_vec(plaintext);
    let ciphertext = string_to_vec(ciphertext);
    // 1. Try each combinations of key-value pair to eliminate impossible pairs
    let mut disproof_table = DisproofTable::new();
    let mut disproof_stats = DisproofStatsCollector::new();
    for ciphertext_symbol in 0..27 {
        for plaintext_symbol in 0..27 {
            if try_disprove_pair(
                ciphertext_symbol,
                plaintext_symbol,
                &ciphertext,
                &plaintext,
                &mut disproof_stats,
            ) {
                disproof_table
                    .write_disproven_pair(ciphertext_symbol, plaintext_symbol)
            }
        }
    }
    println!("{disproof_table}");
    println!("{disproof_stats}");
    false
}

// Return whether the pair is disproven
pub fn try_disprove_pair(
    ciphertext_symbol: u8,
    plaintext_symbol: u8,
    ciphertext: &[u8],
    plaintext: &[u8],
    stats: &mut DisproofStatsCollector,
) -> bool {
    let noise = ciphertext.len() - plaintext.len();
    // 1. Direct length comparison.
    let ciphertext_pop = bytecount::count(ciphertext, ciphertext_symbol);
    let plaintext_pop = bytecount::count(plaintext, plaintext_symbol);
    if ciphertext_pop < plaintext_pop || ciphertext_pop > plaintext_pop + noise
    {
        stats.increment_length_disproof();
        return true;
    }
    false
}

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
