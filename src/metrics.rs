use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;

pub struct MetricsRegistry {
    counters: Mutex<HashMap<String, u64>>,
}

impl MetricsRegistry {
    fn new() -> Self {
        MetricsRegistry {
            counters: Mutex::new(HashMap::new()),
        }
    }

    pub fn increment_counter(&self, name: &str) {
        let mut counters = self.counters.lock().unwrap();
        let counter = counters.entry(name.to_owned()).or_insert(0);
        *counter += 1;
    }

    pub fn get_counter_value(&self, name: &str) -> Option<u64> {
        let counters = self.counters.lock().unwrap();
        counters.get(name).copied()
    }
}

pub static REGISTRY: Lazy<MetricsRegistry> = Lazy::new(MetricsRegistry::new);

#[macro_export]
macro_rules! inc_counter {
    ($name:expr) => {
        crate::metrics::REGISTRY.increment_counter($name)
    };
}

#[macro_export]
macro_rules! get_counter {
    ($name:expr) => {{
        match crate::metrics::REGISTRY.get_counter_value($name) {
            Some(value) => value,
            None => {
                eprintln!("Warning: Counter '{}' not found.", $name);
                0
            }
        }
    }};
}
