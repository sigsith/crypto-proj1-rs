use rand::{seq::SliceRandom, Rng};
pub fn gen_challenge<T: Rng>(
    plaintext_candidates: &[&str],
    randomness: f64,
    rng: &mut T,
) -> String {
    let key = gen_key(rng);
    let Some(chosen) = plaintext_candidates.choose(rng) else {
        return String::new();
    };
    let plaintext_vec = string_to_vec(chosen);
    let result = mono_alpha_sub(&plaintext_vec, &key, randomness, rng);
    slice_to_string(&result)
}

pub fn mono_alpha_sub<T: Rng>(
    plaintext: &[u8],
    key: &[u8; 27],
    randomness: f64,
    rng: &mut T,
) -> Vec<u8> {
    debug_assert!((0.0..1.0).contains(&randomness));
    let mut ciphertext = Vec::new();
    let mut index = 0;
    while index < plaintext.len() {
        if toss_coin_with_probability(rng, randomness) {
            ciphertext.push(rng.gen_range(0..27));
        } else {
            let plaintext_char = plaintext[index];
            let encrypted = key[plaintext_char as usize];
            ciphertext.push(encrypted);
            index += 1;
        }
    }
    ciphertext
}

// Input must be validated.
pub fn string_to_vec(text: &str) -> Vec<u8> {
    text.chars().map(char_to_u8).collect()
}

fn slice_to_string(vector: &[u8]) -> String {
    vector.iter().map(|num: &u8| u8_to_char(*num)).collect()
}

const fn char_to_u8(character: char) -> u8 {
    match character {
        'a'..='z' => character as u8 - b'a',
        ' ' => 26,
        _ => unreachable!(),
    }
}

const fn u8_to_char(num: u8) -> char {
    match num {
        0..=25 => (num + b'a') as char,
        26 => ' ',
        _ => unreachable!(),
    }
}

fn toss_coin_with_probability<T: Rng>(rng: &mut T, probability: f64) -> bool {
    let throw = rng.gen::<f64>();
    throw < probability
}

pub fn gen_key<T: Rng>(rng: &mut T) -> [u8; 27] {
    let mut array = [0u8; 27];
    array.iter_mut().enumerate().for_each(|(i, item)| {
        *item = i as u8;
    });
    array.shuffle(rng);
    array
}
