mod disproof_table;

use crate::encryption::string_to_vec;
use disproof_table::DisproofTable;
use rand::{seq::SliceRandom, thread_rng};

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
    // 3. Todo: Attempt to find out which plaintext is most likely.
    // let mut rng = thread_rng();
    // let random_pick = not_refuted.choose(&mut rng)?;
    // Some(plaintext_candidates[*random_pick].to_owned())
    let ciphertext_dist =
        calculate_frequency_distribution(&string_to_vec(ciphertext));
    let mut min_diff = usize::MAX;
    let mut best = 0;
    for item in not_refuted {
        let plaintext = string_to_vec(plaintext_candidates[item]);
        let plaintext_dist = calculate_frequency_distribution(&plaintext);
        let diff =
            calculate_overall_difference(&plaintext_dist, &ciphertext_dist);
        if diff < min_diff {
            best = item;
            min_diff = diff;
        }
    }
    Some(plaintext_candidates[best].to_owned())
}

fn calculate_frequency_distribution(text: &[u8]) -> [usize; 27] {
    let mut frequency_distribution = [0; 27];
    for &symbol in text {
        frequency_distribution[symbol as usize] += 1;
    }
    frequency_distribution.sort_unstable();
    frequency_distribution
}

fn calculate_overall_difference(
    sorted_a: &[usize],
    sorted_b: &[usize],
) -> usize {
    sorted_a
        .iter()
        .zip(sorted_b.iter())
        .fold(0, |acc, (&a, &b)| {
            acc + (a as isize - b as isize).unsigned_abs()
        })
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

// Performs a basic scan of the disproof table.
// Returns Ok(Vec<(u8, u8)>), the vector is a list of up to 27 axiomatic pairs.
// Returns Err(()) if there are obvious inconsistencies.
//
// An axiomatic pair is a subsitution pair which is assumed to be true due to
// a lack of alternatives.
pub fn scan_disproof_table(
    disproof_table: &DisproofTable,
) -> Result<Vec<(u8, u8)>, ()> {
    let mut axioms = Vec::new();
    let mut occupied_ciphertext_symbols = [false; 27];
    let mut occupied_plaintext_symbols = [false; 27];
    for c in 0..27 {
        let mut n_disproven = 0;
        let mut last_undisproven = 0;
        for p in 0..27 {
            if disproof_table.is_disproven(c, p) {
                n_disproven += 1;
            } else {
                last_undisproven = p
            }
        }
        if n_disproven == 27 {
            #[cfg(feature = "metrics")]
            inc_counter!("no_solution");
            return Err(());
        } else if n_disproven == 26 {
            let axiom_c = c;
            let axiom_p = last_undisproven;
            if occupied_ciphertext_symbols[axiom_c as usize]
                || occupied_plaintext_symbols[axiom_p as usize]
            {
                #[cfg(feature = "metrics")]
                inc_counter!("axiomatic_contradiction");
                return Err(());
            }
            occupied_ciphertext_symbols[axiom_c as usize] = true;
            occupied_plaintext_symbols[axiom_p as usize] = true;
            axioms.push((axiom_c, axiom_p));
        }
    }
    for p in 0..27 {
        let mut n_disproven = 0;
        let mut last_undisproven = 0;
        for c in 0..27 {
            if disproof_table.is_disproven(c, p) {
                n_disproven += 1;
            } else {
                last_undisproven = c
            }
        }
        if n_disproven == 27 {
            #[cfg(feature = "metrics")]
            inc_counter!("no_solution");
            return Err(());
        } else if n_disproven == 26 {
            let axiom_c = last_undisproven;
            let axiom_p = p;
            // It is possible that an axiom is both a row and a column axiom
            if axioms.contains(&(axiom_c, axiom_p)) {
                continue;
            }
            if occupied_ciphertext_symbols[axiom_c as usize]
                || occupied_plaintext_symbols[axiom_p as usize]
            {
                #[cfg(feature = "metrics")]
                inc_counter!("axiomatic_contradiction");
                return Err(());
            }
            occupied_ciphertext_symbols[axiom_c as usize] = true;
            occupied_plaintext_symbols[axiom_p as usize] = true;
            axioms.push((axiom_c, axiom_p));
        }
    }
    Ok(axioms)
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
    // 1. Try each combinations of key-value pair to eliminate impossible pairs
    for ciphertext_symbol in 0..27 {
        for plaintext_symbol in 0..27 {
            if disprove_pair(
                ciphertext_symbol,
                plaintext_symbol,
                &ciphertext,
                &plaintext,
            ) {
                disproof_table
                    .write_disproven(ciphertext_symbol, plaintext_symbol)
            }
        }
    }
    let mut axiomatic_pairs = match scan_disproof_table(disproof_table) {
        Ok(item) => item,
        Err(()) => return true,
    };
    #[cfg(feature = "metrics")]
    inc_counter_by!("n_starting_axiomatic_pairs", axiomatic_pairs.len() as u64);
    // 2. Secondary disproofs. Combining one proven pair and one unproven pair,
    // to see if the resulting pair enables plaintext segments are vali
    // substring of the correponding ciphertext segments
    // let is_disproven = secondary_disproof(
    //     &mut axiomatic_pairs,
    //     disproof_table,
    //     &ciphertext,
    //     &plaintext,
    // );
    // if is_disproven {
    //     return true;
    // }
    false
}

// pub fn secondary_disproof(
//     valid_pairs: &mut Vec<(u8, u8)>,
//     disproof_table: &mut DisproofTable,
//     ciphertext: &[u8],
//     plaintext: &[u8],
// ) -> bool {
//     let mut valid_index = 0;
//     // For each valid_pair, check against pairs that are neither disproven, nor
//     // necessarily valid.
//     while valid_index < valid_pairs.len() {
//         let valid_pair = valid_pairs[valid_index];
//         for cipher_symbol in 0..27 {
//             for plaintext_symbol in 0..27 {
//                 if disproof_table.is_disproven(cipher_symbol, plaintext_symbol)
//                 {
//                     continue;
//                 }
//                 let test_pair = (cipher_symbol, plaintext_symbol);
//                 if valid_pairs.contains(&test_pair) {
//                     continue;
//                 }
//                 let is_disproven = try_disprove_double_pair(
//                     valid_pair, test_pair, ciphertext, plaintext,
//                 );
//                 if is_disproven {
//                     disproof_table
//                         .write_disproven(cipher_symbol, plaintext_symbol);
//                     // Check if updated pair lead to total elimination
//                     if disproof_table
//                         .is_ciphertext_symbol_fully_eliminated(cipher_symbol)
//                         || disproof_table.is_plaintext_symbol_fully_eliminated(
//                             plaintext_symbol,
//                         )
//                     {
//                         return true;
//                     }
//                     // Check if updated pair lead to more valid pairs
//                     if let Some(valid_pair) = disproof_table
//                         .check_valid_pair_at_cipher_symbol(cipher_symbol)
//                     {
//                         if !valid_pairs.contains(&valid_pair) {
//                             valid_pairs.push(valid_pair)
//                         }
//                     }
//                     if let Some(valid_pair) = disproof_table
//                         .check_valid_pair_at_plaintext_symbol(plaintext_symbol)
//                     {
//                         if !valid_pairs.contains(&valid_pair) {
//                             valid_pairs.push(valid_pair)
//                         }
//                     }
//                     // Check if these valid pairs are in conflicts
//                     // if check_conflicting_valid_pairs(valid_pairs) {
//                     //     return true;
//                     // }
//                 }
//             }
//         }
//         valid_index += 1;
//     }
//     false
// }

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

// Returns whether a substitution pair is disproven.
pub fn disprove_pair(
    ciphertext_symbol: u8,
    plaintext_symbol: u8,
    ciphertext: &[u8],
    plaintext: &[u8],
) -> bool {
    #[cfg(feature = "metrics")]
    inc_counter!("pair_disproof_attempts");
    let noise = ciphertext.len() - plaintext.len();
    // 1. Direct length comparison.
    if test_direct_length(
        ciphertext_symbol,
        plaintext_symbol,
        ciphertext,
        plaintext,
        noise,
    ) {
        #[cfg(feature = "metrics")]
        inc_counter!("pair_disproof_lenth_cmp");
        return true;
    }
    // 2. Compare alignments
    // Given that ciphertext is just a tranform of the plaintext with extra
    // noise, the coorespoonding ciphertext symbol cannot be more than an offset
    // away from the plaintext symbol

    if test_alignment(
        ciphertext_symbol,
        plaintext_symbol,
        ciphertext,
        plaintext,
        noise,
    ) {
        #[cfg(feature = "metrics")]
        inc_counter!("pair_disproof_align");
        return true;
    }
    #[cfg(feature = "metrics")]
    inc_counter!("pair_disproof_fail");
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

fn test_alignment(
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
