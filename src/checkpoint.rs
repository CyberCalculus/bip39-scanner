use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub current_index: u64,
    pub total_combinations: u64,
    pub scanned_count: u64,
    pub found_address: Option<String>,
    pub start_time: u64,
    pub last_update: u64,
    pub tickets_completed: Vec<u64>,
    pub state: ScanState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanState {
    NotStarted,
    Running,
    Paused,
    Completed,
    Found,
}

impl Checkpoint {
    pub fn new(total: u64) -> Self {
        let now = timestamp();
        Self {
            current_index: 0,
            total_combinations: total,
            scanned_count: 0,
            found_address: None,
            start_time: now,
            last_update: now,
            tickets_completed: Vec::new(),
            state: ScanState::NotStarted,
        }
    }

    pub fn save(&self, path: &str) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize checkpoint: {}", e))?;
        let tmp = format!("{}.tmp", path);
        std::fs::write(&tmp, &json)
            .map_err(|e| format!("Failed to write checkpoint: {}", e))?;
        std::fs::rename(&tmp, path)
            .map_err(|e| format!("Failed to rename checkpoint: {}", e))?;
        Ok(())
    }

    pub fn load(path: &str) -> Result<Self, String> {
        if !Path::new(path).exists() {
            return Err("Checkpoint file does not exist".into());
        }
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read checkpoint: {}", e))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse checkpoint: {}", e))
    }

    pub fn update(&mut self, index: u64, count: u64) {
        self.current_index = index;
        self.scanned_count = count;
        self.last_update = timestamp();
    }

    pub fn mark_ticket_done(&mut self, ticket_id: u64) {
        if !self.tickets_completed.contains(&ticket_id) {
            self.tickets_completed.push(ticket_id);
        }
    }

    pub fn elapsed_seconds(&self) -> u64 {
        self.last_update.saturating_sub(self.start_time)
    }

    pub fn rate(&self) -> f64 {
        let elapsed = self.elapsed_seconds() as f64;
        if elapsed > 0.0 {
            self.scanned_count as f64 / elapsed
        } else {
            0.0
        }
    }

    pub fn progress_pct(&self) -> f64 {
        if self.total_combinations > 0 {
            (self.scanned_count as f64 / self.total_combinations as f64) * 100.0
        } else {
            0.0
        }
    }
}

fn timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
