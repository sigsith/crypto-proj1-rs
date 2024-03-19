use std::fmt::Display;

#[derive(Default)]
pub struct DisproofStatsCollector {
    length_disproof: usize,
}

impl DisproofStatsCollector {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn increment_length_disproof(&mut self) {
        self.length_disproof += 1;
    }
}

impl Display for DisproofStatsCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total = self.length_disproof;
        let max_dispoof = f64::from(27 * 27);
        writeln!(
            f,
            "Total disproof: {total}/{max_dispoof}, {:.2}%",
            total as f64 / max_dispoof * 100.0
        )?;
        write_one_entry(f, "Length dispoof", self.length_disproof, total)
    }
}

fn write_one_entry(
    f: &mut std::fmt::Formatter<'_>,
    entry_name: &str,
    count: usize,
    total: usize,
) -> std::fmt::Result {
    write!(
        f,
        "{entry_name}: {}/{}, {:.2}%",
        count,
        total,
        count as f64 / total as f64 * 100.0
    )
}
