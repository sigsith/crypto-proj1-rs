mod disproof_stats;
mod disproof_table;

use self::disproof_table::DisproofTable;
use crate::{
    algo::disproof_stats::DisproofStatsCollector, encryption::string_to_vec,
};

#[cfg(feature = "metrics")]
use crate::{get_counter, inc_counter};

pub fn apply_cryptanalysis(
    plaintext_candidates: &[&str],
    ciphertext: &str,
) -> Option<String> {
    #[cfg(feature = "metrics")]
    inc_counter!("total_runs");
    // Validate that the plaintexts and the ciphertext are coorectly formatted.
    validate_input(plaintext_candidates, ciphertext).ok()?;
    // Try each plaintext-ciphertext pair to see if any matches
    let mut disproved = vec![false; plaintext_candidates.len()];
    for i in 0..plaintext_candidates.len() {
        let mut disprove_table = DisproofTable::new();
        let mut disproof_stats = DisproofStatsCollector::new();
        if disprove_plaintext_ciphertext_pair(
            plaintext_candidates[i],
            ciphertext,
            &mut disprove_table,
            &mut disproof_stats,
        ) {
            disproved[i] = true;
        }
        println!("{disprove_table}");
        println!("{disproof_stats}");
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
    disproof_table: &mut DisproofTable,
    disproof_stats: &mut DisproofStatsCollector,
) -> bool {
    // 0. Convert plaintext and ciphertext to integer representations.
    let plaintext = string_to_vec(plaintext);
    let ciphertext = string_to_vec(ciphertext);
    // 1. Try each combinations of key-value pair to eliminate impossible pairs
    for ciphertext_symbol in 0..27 {
        for plaintext_symbol in 0..27 {
            if try_disprove_pair(
                ciphertext_symbol,
                plaintext_symbol,
                &ciphertext,
                &plaintext,
                disproof_stats,
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
    let mut valid_pairs = disproof_table.find_all_proven_pairs();
    if check_conflicting_valid_pairs(&valid_pairs) {
        println!("Disproven through conflicting valid_pairs");
        return true;
    }
    // 2. Secondary disproofs. Combining one proven pair and one unproven pair,
    // to see if the resulting pair enables plaintext segments are vali
    // substring of the correponding ciphertext segments
    let is_disproven = secondary_disproof(
        &mut valid_pairs,
        disproof_table,
        &ciphertext,
        &plaintext,
        disproof_stats,
    );
    if is_disproven {
        println!("Disproven through secondary elimination!");
        return true;
    }
    false
}

// Valid pairs cannot share ciphertext or plaintext symbols
pub fn check_conflicting_valid_pairs(valid_pairs: &[(u8, u8)]) -> bool {
    let mut registered_ciphertext_symbols = [false; 27];
    let mut registered_plaintext_symbols = [false; 27];
    for (ciphertext_symbol, plaintext_symbol) in valid_pairs {
        if registered_ciphertext_symbols[*ciphertext_symbol as usize] {
            return true;
        }
        registered_ciphertext_symbols[*ciphertext_symbol as usize] = true;
        if registered_plaintext_symbols[*plaintext_symbol as usize] {
            return true;
        }
        registered_plaintext_symbols[*plaintext_symbol as usize] = true
    }
    false
}

pub fn secondary_disproof(
    valid_pairs: &mut Vec<(u8, u8)>,
    disproof_table: &mut DisproofTable,
    ciphertext: &[u8],
    plaintext: &[u8],
    stats: &mut DisproofStatsCollector,
) -> bool {
    let mut valid_index = 0;
    // For each valid_pair, check against pairs that are neither disproven, nor
    // necessarily valid.
    while valid_index < valid_pairs.len() {
        let valid_pair = valid_pairs[valid_index];
        for cipher_symbol in 0..27 {
            for plaintext_symbol in 0..27 {
                if disproof_table.is_disproven(cipher_symbol, plaintext_symbol)
                {
                    continue;
                }
                let test_pair = (cipher_symbol, plaintext_symbol);
                if valid_pairs.contains(&test_pair) {
                    continue;
                }
                let is_disproven = try_disprove_double_pair(
                    valid_pair, test_pair, ciphertext, plaintext,
                );
                if is_disproven {
                    stats.increment_secondary_disproof();
                    disproof_table
                        .write_disproven_pair(cipher_symbol, plaintext_symbol);
                    // Check if updated pair lead to total elimination
                    if disproof_table
                        .is_ciphertext_symbol_fully_eliminated(cipher_symbol)
                        || disproof_table.is_plaintext_symbol_fully_eliminated(
                            plaintext_symbol,
                        )
                    {
                        return true;
                    }
                    // Check if updated pair lead to more valid pairs
                    if let Some(valid_pair) = disproof_table
                        .check_valid_pair_at_cipher_symbol(cipher_symbol)
                    {
                        if !valid_pairs.contains(&valid_pair) {
                            valid_pairs.push(valid_pair)
                        }
                    }
                    if let Some(valid_pair) = disproof_table
                        .check_valid_pair_at_plaintext_symbol(plaintext_symbol)
                    {
                        if !valid_pairs.contains(&valid_pair) {
                            valid_pairs.push(valid_pair)
                        }
                    }
                    // Check if these valid pairs are in conflicts
                    // if check_conflicting_valid_pairs(valid_pairs) {
                    //     return true;
                    // }
                }
            }
        }
        valid_index += 1;
    }
    false
}

pub fn try_disprove_double_pair(
    pair1: (u8, u8),
    pair2: (u8, u8),
    ciphertext: &[u8],
    plaintext: &[u8],
) -> bool {
    let mut cipher_idx = 0;
    for &plaintext_symbol in plaintext {
        let cipher_symbol = if plaintext_symbol == pair1.1 {
            pair1.0
        } else if plaintext_symbol == pair2.1 {
            pair2.0
        } else {
            continue;
        };
        match find_cipher_symbol(ciphertext, cipher_idx, cipher_symbol) {
            Ok(found_idx) => cipher_idx = found_idx + 1,
            Err(()) => return true,
        }
    }
    false
}

fn find_cipher_symbol(
    ciphertext: &[u8],
    start: usize,
    symbol: u8,
) -> Result<usize, ()> {
    let mut index = start;
    while index < ciphertext.len() {
        if ciphertext[index] == symbol {
            return Ok(index);
        }
        index += 1;
    }
    Err(())
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
    // // 2.2 Right alignment:
    // if test_right_alignment(
    //     ciphertext_symbol,
    //     plaintext_symbol,
    //     ciphertext,
    //     plaintext,
    //     noise,
    // ) {
    //     stats.increment_right_alignment_disproof();
    //     return true;
    // }
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
                Err(()) => return true,
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

// // Similar logic as left alignment
// fn test_right_alignment(
//     ciphertext_symbol: u8,
//     plaintext_symbol: u8,
//     ciphertext: &[u8],
//     plaintext: &[u8],
//     noise: usize,
// ) -> bool {
//     let mut plaintext_index = plaintext.len() - 1;
//     let mut noise_used = 0;
//     loop {
//         if plaintext[plaintext_index] == plaintext_symbol {
//             let right_aligned_index =
//                 ciphertext.len() - (plaintext.len() - plaintext_index);
//             match check_right_alignment_offset(
//                 right_aligned_index,
//                 ciphertext,
//                 ciphertext_symbol,
//                 noise_used,
//                 noise,
//             ) {
//                 Ok(extra) => noise_used += extra,
//                 Err(_) => return true,
//             }
//         }
//         if plaintext_index == 0 {
//             break;
//         }
//         plaintext_index -= 1
//     }
//     false
// }

// fn check_right_alignment_offset(
//     right_aligned_start: usize,
//     ciphertext: &[u8],
//     ciphertext_symbol: u8,
//     noise_used: usize,
//     total_noise: usize,
// ) -> Result<usize, ()> {
//     let starting_index = right_aligned_start - noise_used;
//     let ending_index = right_aligned_start - total_noise;
//     for i in (ending_index..=starting_index).rev() {
//         if ciphertext[i] == ciphertext_symbol {
//             return Ok(starting_index - i);
//         }
//     }
//     Err(())
// }

fn validate_input(
    plaintext_candidates: &[&str],
    ciphertext: &str,
) -> Result<(), ()> {
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
    Ok(())
}

fn is_lowercase_or_space(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_lowercase() || c == ' ')
}
