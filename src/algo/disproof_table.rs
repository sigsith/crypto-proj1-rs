// Contains all invalid mappings
pub struct DisproofTable {
    // Cipher to plaintext char pairs
    cipher_to_plain: [[bool; 27]; 27],
}

impl DisproofTable {
    pub const fn new() -> Self {
        Self {
            cipher_to_plain: [[false; 27]; 27],
        }
    }
    pub const fn is_disproven(
        &self,
        ciphertext_symbol: u8,
        plaintext_symbol: u8,
    ) -> bool {
        self.cipher_to_plain[ciphertext_symbol as usize]
            [plaintext_symbol as usize]
    }
    pub fn write_disproven(
        &mut self,
        ciphertext_symbol: u8,
        plaintext_symbol: u8,
    ) {
        self.cipher_to_plain[ciphertext_symbol as usize]
            [plaintext_symbol as usize] = true
    }
}
