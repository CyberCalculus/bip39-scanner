use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub scan: ScanConfig,
    pub performance: PerformanceConfig,
    pub output: OutputConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub target_address: String,
    pub derivation_path: String,
    pub wordlist_path: Option<String>,
    pub passphrase: String,
    pub use_validity_check: bool,
    pub max_depth: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub threads: usize,
    pub batch_size: usize,
    pub checkpoint_interval: u64,
    pub save_progress_every: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub verbose: bool,
    pub show_progress: bool,
    pub log_file: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scan: ScanConfig {
                target_address: String::new(),
                derivation_path: "m/84'/0'/0'/0/0".to_string(),
                wordlist_path: None,
                passphrase: String::new(),
                use_validity_check: true,
                max_depth: None,
            },
            performance: PerformanceConfig {
                threads: 1,
                batch_size: 1000,
                checkpoint_interval: 100000,
                save_progress_every: 50000,
            },
            output: OutputConfig {
                verbose: false,
                show_progress: true,
                log_file: None,
            },
        }
    }
}

impl Config {
    pub fn load(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config: {}", e))?;
        toml::from_str(&content)
            .map_err(|e| format!("Failed to parse config: {}", e))
    }

    pub fn save(&self, path: &str) -> Result<(), String> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;
        std::fs::write(path, content)
            .map_err(|e| format!("Failed to write config: {}", e))
    }

    pub fn default_config_file() -> String {
        let mut config = Self::default();
        config.scan.target_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string();
        config.scan.derivation_path = "m/84'/0'/0'/0/0".to_string();
        config.performance.threads = num_cpus();
        config.performance.checkpoint_interval = 100000;

        toml::to_string_pretty(&config).unwrap()
    }
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}
