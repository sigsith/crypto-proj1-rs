use std::env;
use std::io::Write;
use std::process::{Command, Stdio};

use crypto_proj1_rs::{encryption::gen_challenge, plaintext};

use std::time::{Duration, Instant};

use rand::SeedableRng;
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        print_help(&args);
        return;
    }
    let binary_name = &args[1].trim();
    let Ok(iteration) = args[2].parse::<usize>() else {
        print_help(&args);
        return;
    };
    let Ok(randomness) = args[3].parse::<f64>() else {
        print_help(&args);
        return;
    };
    if !(0.0..1.0).contains(&randomness) {
        print_help(&args);
        return;
    }
    println!("Binary: {binary_name}, Iteration: {iteration}, Randomness: {randomness}");
    let plaintexts = plaintext::get_hardcoded_plaintexts();
    // let mut rng = rand::thread_rng();
    let mut rng = rand::rngs::StdRng::from_seed([42; 32]);
    let mut correct_guess = 0;
    let mut total_duration = Duration::new(0, 0);
    for _ in 0..iteration {
        let (plaintext, cipher_text) =
            gen_challenge(&plaintexts, randomness, &mut rng);
        let start_time = Instant::now();
        let mut child = Command::new(binary_name)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to start process");

        {
            let child_stdin =
                child.stdin.as_mut().expect("Failed to open stdin");
            writeln!(child_stdin, "{}", cipher_text)
                .expect("Failed to write to stdin");
        }
        let output = child.wait_with_output().expect("Failed to read stdout");

        let raw_output =
            String::from_utf8(output.stdout).expect("Output is not UTF-8");
        let result = raw_output.split(':').last().unwrap().trim();

        let end_time = Instant::now();
        total_duration += end_time - start_time;
        if result == plaintext {
            correct_guess += 1;
        }
    }
    println!(
        "Duration: {:?}, Duration/run: {:?}",
        total_duration,
        total_duration / iteration as u32
    );
    println!(
        "Correct guesses: {}, Incorrect guesses: {}",
        correct_guess,
        iteration - correct_guess
    );
    let success_rate = correct_guess as f64 / iteration as f64;
    println!("Success rate: {:.2}%", success_rate * 100.0);
}

fn print_help(args: &[String]) {
    eprintln!("Usage: {} <binary_name> <iteration> <randomness>", args[0]);
}
