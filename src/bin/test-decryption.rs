use std::env;

use crypto_proj1_rs::{
    algo::apply_cryptanalysis, encryption::gen_challenge, plaintext,
};
use rand::SeedableRng;
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        print_help(&args);
        return;
    }
    let Ok(iterations) = args[1].parse::<usize>() else {
        print_help(&args);
        return;
    };
    let Ok(randomness) = args[2].parse::<f64>() else {
        print_help(&args);
        return;
    };
    if !(0.0..1.0).contains(&randomness) {
        print_help(&args);
        return;
    }
    let plaintexts = plaintext::get_hardcoded_plaintexts();
    // let mut rng = rand::thread_rng();
    let mut rng = rand::rngs::StdRng::from_seed([42; 32]);
    let mut correct_guess = 0;
    let mut incorrect_guess = 0;
    let mut unable_to_guess = 0;
    for _ in 0..iterations {
        let (plaintext, cipher_text) =
            gen_challenge(&plaintexts, randomness, &mut rng);
        let result = apply_cryptanalysis(&plaintexts, &cipher_text);
        match result {
            Some(text) => {
                if text == *plaintext {
                    correct_guess += 1;
                } else {
                    incorrect_guess += 1;
                }
            }
            None => {
                unable_to_guess += 1;
            }
        }
    }
    println!("Correct guesses: {correct_guess}, Incorrect guesses: {incorrect_guess}, Unable to guess: {unable_to_guess}");
    let success_rate = correct_guess as f64
        / (correct_guess + incorrect_guess + unable_to_guess) as f64;
    println!("Success rate: {:.2}%", success_rate * 100.0);
}

fn print_help(args: &[String]) {
    eprintln!("Usage: {} <n> <r>", args[0]);
    eprintln!("n: number of times of individual tests");
    eprintln!("r: probability of random ciphertext");
}
