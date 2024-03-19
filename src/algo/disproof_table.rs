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
        self.cipher_to_plain[ciphertext_symbol as usize]
            [plaintext_symbol as usize]
    }
    pub fn write_disproven_pair(
        &mut self,
        ciphertext_symbol: u8,
        plaintext_symbol: u8,
    ) {
        self.cipher_to_plain[ciphertext_symbol as usize]
            [plaintext_symbol as usize] = true
    }
    pub fn is_ciphertext_symbol_fully_eliminated(
        &self,
        ciphertext_symbol: u8,
    ) -> bool {
        self.cipher_to_plain[ciphertext_symbol as usize]
            .iter()
            .all(|&item| item)
    }
    pub fn is_plaintext_symbol_fully_eliminated(
        &self,
        plaintext_symbol: u8,
    ) -> bool {
        for i in 0..27 {
            if !self.cipher_to_plain[i][plaintext_symbol as usize] {
                return false;
            }
        }
        true
    }
    // Returns a Vector of proven (ciphertext_symbol, plaintext_symbol) pairs
    pub fn find_all_proven_pairs(&self) -> Vec<(u8, u8)> {
        // If there are any entries where all but one is eliminated, it must be
        // valid pair.
        let mut valid_pairs = Vec::new();
        // 1. Check from ciphertext:
        for ciphertext_symbol in 0..27 {
            if let Some(valid_pair) =
                self.check_valid_pair_at_cipher_symbol(ciphertext_symbol)
            {
                valid_pairs.push(valid_pair)
            }
        }
        // 2. Check from plaintext:
        for plaintext_symbol in 0..27 {
            if let Some(valid_pair) =
                self.check_valid_pair_at_plaintext_symbol(plaintext_symbol)
            {
                if !valid_pairs.contains(&valid_pair) {
                    valid_pairs.push(valid_pair)
                }
            }
        }
        valid_pairs
    }

    pub fn check_valid_pair_at_cipher_symbol(
        &self,
        ciphertext_symbol: u8,
    ) -> Option<(u8, u8)> {
        let mut false_count = 0;
        let mut false_plaintext = 0;
        for plaintext_symbol in 0..27 {
            if !self.is_disproven(ciphertext_symbol, plaintext_symbol) {
                false_count += 1;
                false_plaintext = plaintext_symbol;
            }
            if false_count > 1 {
                return None;
            }
        }
        Some((ciphertext_symbol, false_plaintext as u8))
    }

    pub fn check_valid_pair_at_plaintext_symbol(
        &self,
        plaintext_symbol: u8,
    ) -> Option<(u8, u8)> {
        let mut false_count = 0;
        let mut false_ciphertext = 0;
        for ciphertext_symbol in 0..27 {
            if !self.is_disproven(ciphertext_symbol, plaintext_symbol) {
                false_count += 1;
                false_ciphertext = ciphertext_symbol;
            }
            if false_count > 1 {
                return None;
            }
        }
        Some((false_ciphertext as u8, plaintext_symbol))
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
