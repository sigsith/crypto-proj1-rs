use std::fmt::Display;

#[derive(Default)]
pub struct DisproofStatsCollector {
    length_disproof: usize,
    left_alignment_disproof: usize,
    right_alignment_disproof: usize,
    secondary_disproof: usize,
}

impl DisproofStatsCollector {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn increment_length_disproof(&mut self) {
        self.length_disproof += 1;
    }
    pub fn increment_left_alignment_disproof(&mut self) {
        self.left_alignment_disproof += 1;
    }
    pub fn increment_right_alignment_disproof(&mut self) {
        self.right_alignment_disproof += 1;
    }
    pub fn increment_secondary_disproof(&mut self) {
        self.secondary_disproof += 1;
    }
}

impl Display for DisproofStatsCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total = self.length_disproof
            + self.left_alignment_disproof
            + self.right_alignment_disproof
            + self.secondary_disproof;
        let max_dispoof = f64::from(27 * 27);
        writeln!(
            f,
            "Total disproof: {total}/{max_dispoof}, {:.2}%",
            total as f64 / max_dispoof * 100.0
        )?;
        write_one_entry(f, "Length dispoof", self.length_disproof, total)?;
        write_one_entry(
            f,
            "Left_alighment_disproof",
            self.left_alignment_disproof,
            total,
        )?;
        write_one_entry(
            f,
            "Right_alighment_disproof",
            self.right_alignment_disproof,
            total,
        )?;
        write_one_entry(f, "Secondary_disproof", self.secondary_disproof, total)
    }
}

fn write_one_entry(
    f: &mut std::fmt::Formatter<'_>,
    entry_name: &str,
    count: usize,
    total: usize,
) -> std::fmt::Result {
    writeln!(
        f,
        "{entry_name}: {}/{}, {:.2}%",
        count,
        total,
        count as f64 / total as f64 * 100.0
    )
}
