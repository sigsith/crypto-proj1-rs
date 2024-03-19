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
    pub fn write_disproven_pair(ciphertext_symbol: u8, plaintext_symbol: u8) {}
}
