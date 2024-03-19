use std::io;
fn main() -> Result<(), io::Error> {
    println!("Enter the ciphertext:");
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let ciphertext = input.trim_end_matches('\n');
    let result = String::new();
    println!("My plaintext guess is:{result}");
    Ok(())
}
