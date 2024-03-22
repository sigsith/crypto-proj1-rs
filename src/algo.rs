mod disproof_table;

use crate::encryption::string_to_vec;
use disproof_table::DisproofTable;

#[cfg(feature = "metrics")]
use crate::{get_counter, inc_counter, inc_counter_by};

pub fn apply_cryptanalysis(
    plaintext_candidates: &[&str],
    ciphertext: &str,
) -> Option<String> {
    #[cfg(feature = "metrics")]
    inc_counter!("total_runs");
    // 0. Validate input.
    validate_input(plaintext_candidates, ciphertext).ok()?;
    // 1. Attempt to disprove every plaintext candidate.
    let mut not_refuted = Vec::new();
    for (index, plaintext) in plaintext_candidates.iter().enumerate() {
        let mut disprove_table = DisproofTable::new();
        #[cfg(feature = "metrics")]
        inc_counter!("n_plaintexts");
        if disprove_plaintext(plaintext, ciphertext, &mut disprove_table) {
            #[cfg(feature = "metrics")]
            inc_counter!("n_disproven_plaintexts");
        } else {
            not_refuted.push(index);
        }
    }
    // 2. If there is exactly one plaintext not disproven, return it.
    if not_refuted.len() == 1 {
        return Some(plaintext_candidates[not_refuted[0]].to_owned());
    }
    debug_assert!(!not_refuted.is_empty());
    // 3. Attempt to find out which plaintext is most likely with freq analysis.
    let ciphertext_dist =
        calculate_frequency_distribution(&string_to_vec(ciphertext), 0);
    let mut min_diff = f64::MAX;
    let mut best = 0;
    for item in not_refuted {
        let plaintext = string_to_vec(plaintext_candidates[item]);
        let plaintext_dist = calculate_frequency_distribution(
            &plaintext,
            ciphertext.len() - plaintext.len(),
        );
        let diff =
            calculate_overall_difference(&plaintext_dist, &ciphertext_dist);
        if diff < min_diff {
            best = item;
            min_diff = diff;
        }
    }
    Some(plaintext_candidates[best].to_owned())
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

pub fn summarize_metrics() {
    #[cfg(feature = "metrics")]
    {
        let total_runs = get_counter!("total_runs");
        println!("Total runs: {total_runs}");
        println!("Plaintext disproof stats:");
        println!(
            "\tPortion of plaintexts disproven: {:.2}%",
            get_counter!("n_disproven_plaintexts") as f64
                / get_counter!("n_plaintexts") as f64
                * 100.0
        );
        println!("Pair disproof stats:");
        let total_pair_disproof_attempts =
            get_counter!("pair_disproof_attempts");
        println!(
            "\tBy length comparison: {:.2}%",
            get_counter!("pair_disproof_lenth_cmp") as f64
                / total_pair_disproof_attempts as f64
                * 100.0
        );
        println!(
            "\tBy alignment: {:.2}%",
            get_counter!("pair_disproof_align") as f64
                / total_pair_disproof_attempts as f64
                * 100.0
        );
        println!(
            "\tFailed: {:.2}%",
            get_counter!("pair_disproof_fail") as f64
                / total_pair_disproof_attempts as f64
                * 100.0
        );
        println!("Plaintext refutation stats:");
        let refutation_attempts = get_counter!("refutation_attempts");
        println!(
            "\tBy no solution: {:.2}%",
            get_counter!("no_solution") as f64 / refutation_attempts as f64
                * 100.0
        );
        println!(
            "\tBy axiomatic contradiction: {:.2}%",
            get_counter!("axiomatic_contradiction") as f64
                / refutation_attempts as f64
                * 100.0
        );
        println!(
            "Avg starting axiomatic pairs per map: {:.2}",
            get_counter!("n_starting_axiomatic_pairs") as f64
                / refutation_attempts as f64
        );
    }
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
    plaintext: &str,
    ciphertext: &str,
    disproof_table: &mut DisproofTable,
) -> bool {
    #[cfg(feature = "metrics")]
    inc_counter!("refutation_attempts");
    // 0. Convert plaintext and ciphertext to integer representations.
    let plaintext = string_to_vec(plaintext);
    let ciphertext = string_to_vec(ciphertext);
    let plaintext_poslist = to_position_list(&plaintext);
    let ciphertext_poslist = to_position_list(&ciphertext);
    let noise = ciphertext.len() - plaintext.len();
    let mut occupied_ciphertext_symbols = [false; 27];
    let mut occupied_plaintext_symbols = [false; 27];
    // 1. Try each combinations of key-value pair to eliminate impossible pairs
    for ciphertext_symbol in 0..27 {
        let mut n_disproven = 0;
        let mut last_undisproven = 0;
        for plaintext_symbol in 0..27 {
            if disprove_pair(
                &ciphertext_poslist[ciphertext_symbol as usize],
                &plaintext_poslist[plaintext_symbol as usize],
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
    #[cfg(feature = "metrics")]
    inc_counter!("pair_disproof_attempts");
    // 1. Direct length comparison.
    let ciphertext_pop = ciphertext_poslist.len();
    let plaintext_pop = plaintext_poslist.len();
    if test_direct_length(ciphertext_pop, plaintext_pop, noise) {
        #[cfg(feature = "metrics")]
        inc_counter!("pair_disproof_lenth_cmp");
        return true;
    }
    // 2. Compare alignments
    // Given that ciphertext is just a tranform of the plaintext with extra
    // noise, the coorespoonding ciphertext symbol cannot be more than an offset
    // away from the plaintext symbol
    if test_alignment(ciphertext_poslist, plaintext_poslist, noise as u16) {
        #[cfg(feature = "metrics")]
        inc_counter!("pair_disproof_align");
        return true;
    }
    #[cfg(feature = "metrics")]
    inc_counter!("pair_disproof_fail");
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
