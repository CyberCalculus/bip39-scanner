use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ticket {
    pub id: u64,
    pub start_index: u64,
    pub end_index: u64,
    pub state: TicketState,
    pub assigned_to: Option<String>,
    pub started_at: Option<u64>,
    pub finished_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TicketState {
    Pending,
    InProgress,
    Completed,
    Failed,
}

impl Ticket {
    pub fn new(id: u64, start_index: u64, end_index: u64) -> Self {
        Self {
            id,
            start_index,
            end_index,
            state: TicketState::Pending,
            assigned_to: None,
            started_at: None,
            finished_at: None,
        }
    }

    pub fn start(&mut self, worker: &str) {
        self.state = TicketState::InProgress;
        self.assigned_to = Some(worker.to_string());
        self.started_at = Some(now());
    }

    pub fn complete(&mut self) {
        self.state = TicketState::Completed;
        self.finished_at = Some(now());
    }

    pub fn fail(&mut self) {
        self.state = TicketState::Failed;
        self.finished_at = Some(now());
    }

    pub fn size(&self) -> u64 {
        self.end_index - self.start_index
    }

    pub fn contains(&self, index: u64) -> bool {
        index >= self.start_index && index < self.end_index
    }
}

pub struct TicketManager {
    pub tickets: Vec<Ticket>,
    pub total: u64,
    pub ticket_size: u64,
}

impl TicketManager {
    pub fn new(total: u64, ticket_size: u64) -> Self {
        let num_tickets = (total + ticket_size - 1) / ticket_size;
        let mut tickets = Vec::with_capacity(num_tickets as usize);

        for i in 0..num_tickets {
            let start = i * ticket_size;
            let end = std::cmp::min(start + ticket_size, total);
            tickets.push(Ticket::new(i, start, end));
        }

        Self {
            tickets,
            total,
            ticket_size,
        }
    }

    pub fn next_pending(&self) -> Option<&Ticket> {
        self.tickets.iter().find(|t| matches!(t.state, TicketState::Pending))
    }

    pub fn next_pending_mut(&mut self) -> Option<&mut Ticket> {
        self.tickets.iter_mut().find(|t| matches!(t.state, TicketState::Pending))
    }

    pub fn completed_count(&self) -> usize {
        self.tickets.iter().filter(|t| matches!(t.state, TicketState::Completed)).count()
    }

    pub fn total_completed(&self) -> u64 {
        self.tickets
            .iter()
            .filter(|t| matches!(t.state, TicketState::Completed))
            .map(|t| t.size())
            .sum()
    }

    pub fn all_done(&self) -> bool {
        self.tickets.iter().all(|t| matches!(t.state, TicketState::Completed))
    }

    pub fn save(&self, path: &str) -> Result<(), String> {
        let json = serde_json::to_string_pretty(&self.tickets)
            .map_err(|e| format!("Failed to serialize tickets: {}", e))?;
        std::fs::write(path, json)
            .map_err(|e| format!("Failed to write tickets: {}", e))
    }

    pub fn load(path: &str, total: u64, ticket_size: u64) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read tickets: {}", e))?;
        let tickets: Vec<Ticket> = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse tickets: {}", e))?;

        Ok(Self {
            tickets,
            total,
            ticket_size,
        })
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
