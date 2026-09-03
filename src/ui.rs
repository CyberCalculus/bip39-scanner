use colored::*;

pub fn init_logger(verbose: bool) {
    if std::env::var("RUST_LOG").is_err() {
        let level = if verbose { "debug" } else { "info" };
        std::env::set_var("RUST_LOG", level);
    }
    env_logger::init();
}

pub fn banner() {
    println!(
        "{}",
        "  ╔══════════════════════════════════════════╗".bright_blue()
    );
    println!(
        "{}",
        "  ║       BIP39 Mnemonic Scanner v0.3.0      ║".bright_blue()
    );
    println!(
        "{}",
        "  ║  Audited crypto · Multi-threaded · CLI   ║".bright_blue()
    );
    println!(
        "{}",
        "  ╚══════════════════════════════════════════╝".bright_blue()
    );
    println!();
}

pub fn section(title: &str) {
    println!("{}", format!("── {} ──────────────────────────────", title).bright_white().bold());
}

pub fn key_val(key: &str, val: &str) {
    println!("  {:<14} {}", key.bright_cyan(), val.bright_white());
}

pub fn key_val_u64(key: &str, val: u64) {
    println!("  {:<14} {}", key.bright_cyan(), val.to_string().bright_white());
}

pub fn key_val_f64(key: &str, val: f64) {
    println!("  {:<14} {}", key.bright_cyan(), format!("{:.2}", val).bright_white());
}

pub fn success(msg: &str) {
    println!("  {} {}", "✓".bright_green().bold(), msg.bright_green());
}

pub fn error(msg: &str) {
    eprintln!("  {} {}", "✗".bright_red().bold(), msg.bright_red());
}

pub fn warn(msg: &str) {
    eprintln!("  {} {}", "⚠".bright_yellow(), msg.bright_yellow());
}

pub fn info(msg: &str) {
    println!("  {} {}", "→".bright_blue(), msg);
}

pub fn match_found(thread_id: usize, mnemonic: &str, addr: &str) {
    println!();
    println!(
        "  {} {}",
        "★ MATCH FOUND ★".bright_green().bold(),
        format!("[thread {}]", thread_id).bright_white()
    );
    println!("  mnemonic : {}", mnemonic.bright_white().bold());
    println!("  address  : {}", addr.bright_green().bold());
    println!();
}

pub fn progress(checked: u64, valid: u64, matches: u64, rate: f64) {
    eprint!(
        "\r  {} checked {} | valid {} | matches {} | {:.0}/s",
        "●".bright_blue(),
        checked.to_string().bright_white(),
        valid.to_string().bright_cyan(),
        matches.to_string().bright_yellow(),
        rate
    );
}

pub fn separator() {
    println!("{}", "────────────────────────────────────────────".dimmed());
}

pub fn result_block(label: &str, value: &str, color: &str) {
    let styled = match color {
        "green" => value.bright_green().bold(),
        "red" => value.bright_red().bold(),
        "yellow" => value.bright_yellow().bold(),
        "cyan" => value.bright_cyan().bold(),
        _ => value.bright_white().bold(),
    };
    println!("  {:<14} {}", label.bright_cyan(), styled);
}

pub fn header_line() {
    println!(
        "  {}",
        "┌──────────────────────────────────────────┐".dimmed()
    );
}

pub fn footer_line() {
    println!(
        "  {}",
        "└──────────────────────────────────────────┘".dimmed()
    );
}

pub fn checkpoint_saved(path: &str, attempts: u64) {
    log::debug!("Checkpoint saved: {} (attempts: {})", path, attempts);
}

pub fn checkpoint_loaded(path: &str, attempts: u64, checked: u64) {
    log::info!(
        "Loaded checkpoint: {} attempts={}, checked={}",
        attempts,
        checked,
        path
    );
}
