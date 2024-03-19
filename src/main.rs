#![warn(clippy::all, clippy::pedantic)]
#![warn(
    clippy::empty_structs_with_brackets,
    clippy::exit,
    clippy::if_then_some_else_none,
    clippy::impl_trait_in_params,
    clippy::mod_module_files,
    clippy::multiple_inherent_impl,
    clippy::panic,
    clippy::partial_pub_fields,
    clippy::same_name_method,
    clippy::separated_literal_suffix,
    clippy::unimplemented,
    clippy::unneeded_field_pattern,
    clippy::unwrap_used
)]
#![allow(
    clippy::unreadable_literal,
    clippy::module_name_repetitions,
    clippy::semicolon_if_nothing_returned,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::if_not_else,
    clippy::must_use_candidate,
    clippy::return_self_not_must_use,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
use std::io;
mod algo;
mod plaintext;

fn main() -> Result<(), io::Error> {
    println!("Enter the ciphertext:");
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let ciphertext = input.trim_end_matches('\n');
    let plaintext_candidates = plaintext::get_hardcoded_plaintexts();
    let result = algo::apply_cryptanalysis(&plaintext_candidates, ciphertext)
        .unwrap_or("None".to_string());
    println!("My plaintext guess is:{result}");
    Ok(())
}
