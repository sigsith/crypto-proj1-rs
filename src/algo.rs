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
    let mut disproved = vec![false; plaintext_candidates.len()];
    for i in 0..plaintext_candidates.len() {
        if disprove_plaintext_ciphertext_pair(
            plaintext_candidates[i],
            ciphertext,
        ) {
            disproved[i] = true;
        }
    }
    let num_disproven = disproved.iter().filter(|&x| *x).count();
    if num_disproven + 1 == disproved.len() {
        for i in 0..disproved.len() {
            if !disproved[i] {
                return Some(plaintext_candidates[i].to_string());
            }
        }
    }
    None
}

// Return whether it is impossible for the plaintext to map to the ciphertext.
pub fn disprove_plaintext_ciphertext_pair(
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
        if disproof_table
            .is_ciphertext_symbol_fully_eliminated(ciphertext_symbol)
        {
            println!("Disproven through ciphertext elimination!");
            return true;
        }
    }
    for plaintext_symbol in 0..27 {
        if disproof_table.is_plaintext_symbol_fully_eliminated(plaintext_symbol)
        {
            println!("Disproven through plaintext elimination!");
            return true;
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
    if test_direct_length(
        ciphertext_symbol,
        plaintext_symbol,
        ciphertext,
        plaintext,
        noise,
    ) {
        stats.increment_length_disproof();
        return true;
    }
    // 2. Compare alignments
    // Given that ciphertext is just a tranform of the plaintext with extra
    // noise, the coorespoonding ciphertext symbol cannot be more than an offset
    // away from the plaintext symbol

    // 2.1 Left alignment:
    if test_left_alignment(
        ciphertext_symbol,
        plaintext_symbol,
        ciphertext,
        plaintext,
        noise,
    ) {
        stats.increment_left_alignment_disproof();
        return true;
    }
    false
}

fn test_direct_length(
    ciphertext_symbol: u8,
    plaintext_symbol: u8,
    ciphertext: &[u8],
    plaintext: &[u8],
    noise: usize,
) -> bool {
    let ciphertext_pop = bytecount::count(ciphertext, ciphertext_symbol);
    let plaintext_pop = bytecount::count(plaintext, plaintext_symbol);
    ciphertext_pop < plaintext_pop || ciphertext_pop > plaintext_pop + noise
}

fn test_left_alignment(
    ciphertext_symbol: u8,
    plaintext_symbol: u8,
    ciphertext: &[u8],
    plaintext: &[u8],
    noise: usize,
) -> bool {
    let mut plaintext_index = 0;
    let mut noise_used = 0;
    while plaintext_index != plaintext.len() {
        if plaintext[plaintext_index] == plaintext_symbol {
            match check_left_alignment_offset(
                plaintext_index,
                ciphertext,
                ciphertext_symbol,
                noise_used,
                noise,
            ) {
                Ok(extra) => noise_used += extra,
                Err(_) => return true,
            }
        }
        plaintext_index += 1;
    }
    false
}

// Check if it is plausible for the plaintext index to map to the cipher text,
// given the noise tolerance.
// If it is plausible , return the noise used.
// If it is not, return Err.
fn check_left_alignment_offset(
    plaintext_index: usize,
    ciphertext: &[u8],
    ciphertext_symbol: u8,
    noise_used: usize,
    total_noise: usize,
) -> Result<usize, ()> {
    let starting_index = plaintext_index + noise_used;
    let ending_index = plaintext_index + total_noise;
    for i in starting_index..=ending_index {
        if ciphertext[i] == ciphertext_symbol {
            return Ok(i - starting_index);
        }
    }
    Err(())
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
