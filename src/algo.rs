mod disproof_table;

use crate::encryption::string_to_vec;
use disproof_table::DisproofTable;

pub fn apply_cryptanalysis(
    plaintext_candidates: &[&str],
    ciphertext: &str,
) -> usize {
    // 1. Attempt to disprove every plaintext candidate.
    let mut not_refuted = Vec::new();
    let ciphertext = &string_to_vec(ciphertext);
    let plaintext_candidates: Vec<Vec<u8>> = plaintext_candidates
        .iter()
        .map(|s| string_to_vec(s))
        .collect();
    let ciphertext_positions = to_position_list(ciphertext);
    for (index, plaintext) in plaintext_candidates.iter().enumerate() {
        if !disprove_plaintext(plaintext, ciphertext, &ciphertext_positions) {
            not_refuted.push(index);
        }
    }
    // 2. If there is exactly one plaintext not disproven, return it.
    if not_refuted.len() == 1 {
        return not_refuted[0];
    }
    debug_assert!(!not_refuted.is_empty());
    // 3. Attempt to find out which plaintext is most likely with freq analysis.
    let ciphertext_dist = calculate_frequency_distribution(ciphertext, 0);
    let mut min_diff = f64::MAX;
    let mut best = 0;
    for item in not_refuted {
        let plaintext = &plaintext_candidates[item];
        let plaintext_dist = calculate_frequency_distribution(
            plaintext,
            ciphertext.len() - plaintext.len(),
        );
        let diff =
            calculate_overall_difference(&plaintext_dist, &ciphertext_dist);
        if diff < min_diff {
            best = item;
            min_diff = diff;
        }
    }
    best
}

fn calculate_frequency_distribution(text: &[u8], noise: usize) -> [f64; 27] {
    let mut frequency_distribution = [0u64; 27];
    for &symbol in text {
        frequency_distribution[symbol as usize] += 1;
    }
    frequency_distribution.sort_unstable();
    let mut float_distribution = [0.0; 27];
    for i in 0..27 {
        let counts = frequency_distribution[i] as f64;
        float_distribution[i] =
            (counts + noise as f64 / 27.0) / (text.len() + noise) as f64;
    }
    float_distribution
}

fn calculate_overall_difference(sorted_a: &[f64], sorted_b: &[f64]) -> f64 {
    sorted_a
        .iter()
        .zip(sorted_b.iter())
        .fold(0.0, |acc, (&a, &b)| acc + (a - b).powi(2))
}

fn to_position_list(text: &[u8]) -> Vec<Vec<u16>> {
    let mut post_list = vec![Vec::new(); 27];
    for (index, &item) in text.iter().enumerate() {
        post_list[item as usize].push(index as u16);
    }
    post_list
}

fn is_conflict_or_insert(
    ciphertext_symbol: u8,
    plaintext_symbol: u8,
    occupied_ciphertext_symbols: &mut [bool; 27],
    occupied_plaintext_symbols: &mut [bool; 27],
) -> bool {
    let condition1 = occupied_ciphertext_symbols[ciphertext_symbol as usize];
    let condition2 = occupied_plaintext_symbols[plaintext_symbol as usize];
    if condition1 && condition2 {
        return false;
    }
    if condition1 || condition2 {
        return true;
    }
    occupied_ciphertext_symbols[ciphertext_symbol as usize] = true;
    occupied_plaintext_symbols[plaintext_symbol as usize] = true;
    false
}

// Returns whether it is impossible for the plaintext to map to the ciphertext.
pub fn disprove_plaintext(
    plaintext: &[u8],
    ciphertext: &[u8],
    ciphertext_positions: &[Vec<u16>],
) -> bool {
    // 0. Convert plaintext and ciphertext to integer representations.
    let plaintext_positions = to_position_list(plaintext);
    let mut disproof_table = DisproofTable::new();
    let noise = ciphertext.len() - plaintext.len();
    let mut occupied_ciphertext_symbols = [false; 27];
    let mut occupied_plaintext_symbols = [false; 27];
    // 1. Try each combination of key-value pair to eliminate impossible pairs
    for ciphertext_symbol in 0..27 {
        let mut n_disproven = 0;
        let mut last_undisproven = 0;
        for plaintext_symbol in 0..27 {
            if disprove_pair(
                &ciphertext_positions[ciphertext_symbol as usize],
                &plaintext_positions[plaintext_symbol as usize],
                noise,
            ) {
                disproof_table
                    .write_disproven(ciphertext_symbol, plaintext_symbol);
                n_disproven += 1;
            } else {
                last_undisproven = plaintext_symbol;
            }
        }
        if n_disproven == 27
            || n_disproven == 26
                && is_conflict_or_insert(
                    ciphertext_symbol,
                    last_undisproven,
                    &mut occupied_ciphertext_symbols,
                    &mut occupied_plaintext_symbols,
                )
        {
            return true;
        }
    }
    for plaintext_symbol in 0..27 {
        let mut n_disproven = 0;
        let mut last_disproven = 0;
        for ciphertext_symbol in 0..27 {
            if disproof_table.is_disproven(ciphertext_symbol, plaintext_symbol)
            {
                n_disproven += 1;
            } else {
                last_disproven = ciphertext_symbol;
            }
        }
        if n_disproven == 27
            || n_disproven == 26
                && is_conflict_or_insert(
                    last_disproven,
                    plaintext_symbol,
                    &mut occupied_ciphertext_symbols,
                    &mut occupied_plaintext_symbols,
                )
        {
            return true;
        }
    }
    false
}

// Returns whether a substitution pair is disproven.
pub fn disprove_pair(
    ciphertext_poslist: &[u16],
    plaintext_poslist: &[u16],
    noise: usize,
) -> bool {
    // 1. Direct length comparison.
    let ciphertext_pop = ciphertext_poslist.len();
    let plaintext_pop = plaintext_poslist.len();
    if test_direct_length(ciphertext_pop, plaintext_pop, noise) {
        return true;
    }
    // 2. Compare alignments
    // Given that ciphertext is just a transform of the plaintext with extra
    // noise, the corresponding ciphertext symbol cannot be more than an offset
    // away from the plaintext symbol
    if test_alignment(ciphertext_poslist, plaintext_poslist, noise as u16) {
        return true;
    }
    false
}

const fn test_direct_length(
    ciphertext_pop: usize,
    plaintext_pop: usize,
    noise: usize,
) -> bool {
    ciphertext_pop < plaintext_pop || ciphertext_pop > plaintext_pop + noise
}

fn test_alignment(
    ciphertext_symbol_poslist: &[u16],
    plaintext_symbol_poslist: &[u16],
    total_noise: u16,
) -> bool {
    let mut noise_used = 0;
    let mut ciphertext_iter = ciphertext_symbol_poslist.iter();
    for &plaintext_index in plaintext_symbol_poslist {
        let start_pos = plaintext_index + noise_used;
        let end_pos = plaintext_index + total_noise;
        loop {
            let Some(&cipher_pos) = ciphertext_iter.next() else {
                return true;
            };
            if cipher_pos < start_pos {
                continue;
            }
            if cipher_pos <= end_pos {
                noise_used += cipher_pos - start_pos;
                break;
            }
            return true;
        }
    }
    false
}
