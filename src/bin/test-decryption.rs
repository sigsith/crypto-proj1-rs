use std::env;

use crypto_proj1_rs::{
    algo::apply_cryptanalysis, encryption::gen_challenge, plaintext,
};
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
    let mut rng = rand::thread_rng();
    for _ in 0..iterations {
        let (plaintext, cipher_text) =
            gen_challenge(&plaintexts, randomness, &mut rng);
        let result = apply_cryptanalysis(&plaintexts, &cipher_text);
        match result {
            Some(text) => {
                if text == *plaintext {
                    println!("Correctly chosen plaintext");
                } else {
                    println!("Wrong plaintext chosen");
                }
            }
            None => {
                println!("Unable to find the corresponding plaintext");
            }
        }
    }
}

fn print_help(args: &[String]) {
    eprintln!("Usage: {} <n> <r>", args[0]);
    eprintln!("n: number of times of individual tests");
    eprintln!("r: probability of random ciphertext");
}
