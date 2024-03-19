use std::fmt::Display;

// Contains all invalid mappings
pub struct DisproofTable {
    // Cipher to plaintext char pairs
    cipher_to_plain: [[bool; 27]; 27],
}

impl DisproofTable {
    pub fn new() -> Self {
        Self {
            cipher_to_plain: [[false; 27]; 27],
        }
    }
    pub fn is_disproven(
        &self,
        ciphertext_symbol: u8,
        plaintext_symbol: u8,
    ) -> bool {
        todo!()
    }
    pub fn write_disproven_pair(
        &mut self,
        ciphertext_symbol: u8,
        plaintext_symbol: u8,
    ) {
        self.cipher_to_plain[ciphertext_symbol as usize]
            [plaintext_symbol as usize] = true
    }
}

impl Display for DisproofTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for row in &self.cipher_to_plain {
            for &cell in row {
                let symbol = if cell { '1' } else { '0' };
                write!(f, "{symbol} ")?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}
