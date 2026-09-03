use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Instant;

use clap::{Parser, Subcommand};

use bip39_scanner::bip39::Bip39;
use bip39_scanner::bip32::Bip32;
use bip39_scanner::checkpoint::{timestamp as cp_timestamp, CheckCheckpoint, Checkpoint, ScanState};
use bip39_scanner::config::Config;
use bip39_scanner::ticket::TicketManager;
use bip39_scanner::ui;

#[derive(Parser)]
#[command(name = "bip39-scanner")]
#[command(
    about = "BIP39 mnemonic scanner with checkpoint and ticket system. \
             All crypto delegated to audited crates (k256, bech32, sha2, ripemd, hmac, pbkdf2, getrandom). \
             Multi-threaded via std::thread."
)]
#[command(version, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan the BIP39 12-word mnemonic space for a target bech32 address.
    ///
    /// Examples:
    ///   bip39-scanner scan -t bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
    ///   bip39-scanner scan --prefix bc1qw --checkpoint cp.json --resume
    ///   bip39-scanner scan --targets targets.txt --export-match found.txt
    Scan {
        /// Mnemonic to check (used with --validity). Otherwise the scanner walks the full space.
        #[arg(short, long)]
        mnemonic: Option<String>,

        /// Full target bech32 address (mutually exclusive with --prefix / --targets).
        #[arg(short, long)]
        target: Option<String>,

        /// Vanity prefix to match on the address (e.g. "bc1qw"). Stops at first hit.
        #[arg(long)]
        prefix: Option<String>,

        /// Path to a file with one target address per line.
        #[arg(long)]
        targets: Option<String>,

        /// BIP32 derivation path.
        #[arg(short, long)]
        path: Option<String>,

        /// Optional BIP39 passphrase.
        #[arg(short, long, default_value = "")]
        passphrase: String,

        /// Path to a TOML config file. CLI flags override config-file values.
        #[arg(long)]
        config: Option<String>,

        /// Path to the checkpoint file. Used for resume + progress saving.
        #[arg(long)]
        checkpoint: Option<String>,

        /// Resume from the saved checkpoint index instead of starting at 0.
        #[arg(long)]
        resume: bool,

        /// Number of mnemonics per ticket (used by the ticket manager).
        #[arg(long)]
        tickets: Option<u64>,

        /// Interpret --mnemonic as a single mnemonic to validate (no scan loop).
        #[arg(long)]
        validity: bool,

        /// Save progress every N mnemonics (overrides config).
        #[arg(long)]
        save_every: Option<u64>,

        /// Append a hit record (mnemonic, address, index, timestamp) to this file.
        #[arg(long)]
        export_match: Option<String>,

        /// Print per-batch progress to stderr.
        #[arg(short, long)]
        verbose: bool,
    },
    /// Validate a single mnemonic and print the derived first address.
    Validate {
        /// The mnemonic phrase (12/15/18/21/24 words).
        #[arg(short, long)]
        mnemonic: String,

        /// Optional BIP39 passphrase.
        #[arg(short, long, default_value = "")]
        passphrase: String,

        /// BIP32 derivation path.
        #[arg(short, long, default_value = "m/84'/0'/0'/0/0")]
        path: String,
    },
    /// Check a 12-word BIP39 mnemonic against one or more target addresses.
    ///
    /// Use --mnemonic for a single phrase, or --mnemonics-file for a batch
    /// (one phrase per line). Returns exit code 0 only if every phrase is valid
    /// and at least one matches the target; exit code 3 if no match.
    ///
    /// Examples:
    ///   bip39-scanner check -m "abandon × 11 about" -t bc1q...
    ///   bip39-scanner check -t bc1q... --mnemonics-file candidates.txt
    ///   bip39-scanner check -t bc1q... --targets-file more-targets.txt
    Check {
        /// A single 12-word mnemonic to check.
        #[arg(short, long)]
        mnemonic: Option<String>,

        /// File with one 12-word mnemonic per line to check in batch.
        #[arg(long)]
        mnemonics_file: Option<String>,

        /// Single target bech32 address.
        #[arg(short = 't', long)]
        target: Option<String>,

        /// Vanity prefix to match (e.g. "bc1qw"). Hits on any address starting with it.
        #[arg(long)]
        prefix: Option<String>,

        /// File with one target address per line. Hits if any target matches.
        #[arg(long)]
        targets_file: Option<String>,

        /// Optional BIP39 passphrase.
        #[arg(short = 'p', long, default_value = "")]
        passphrase: String,

        /// BIP32 derivation path.
        #[arg(long, default_value = "m/84'/0'/0'/0/0")]
        path: String,

        /// Stop at the first matching mnemonic instead of checking every phrase.
        #[arg(long)]
        stop_on_first_match: bool,

        /// Quiet mode: only print the matching lines (useful for piping).
        #[arg(short, long)]
        quiet: bool,

        /// Generate this many random 12-word mnemonics and check each against
        /// the target. Requires one of --target/--prefix/--targets-file.
        /// When combined with --mnemonics-file or --mnemonic, random phrases
        /// are appended after the supplied ones.
        #[arg(long)]
        random: Option<u32>,

        /// Maximum number of random attempts before giving up (0 = unlimited).
        #[arg(long, default_value_t = 0)]
        max_attempts: u32,

        /// Path to checkpoint file for --random mode. Saves progress so it can
        /// be resumed later with --resume.
        #[arg(long)]
        checkpoint: Option<String>,

        /// Resume from the saved checkpoint instead of starting fresh.
        #[arg(long)]
        resume: bool,

        /// Number of worker threads (default: auto-detect from CPU count).
        #[arg(short = 'T', long)]
        threads: Option<usize>,

        /// Space-separated list of 12 words to permute. Checks all 12! orderings
        /// against the target. Only valid-BIP39 permutations are tested.
        #[arg(long, num_args = 1..)]
        words: Option<Vec<String>>,

        /// Number of random word shuffles to test (instead of all permutations).
        #[arg(long)]
        random_shuffles: Option<u64>,

        /// Number of tickets for work distribution (default: 1).
        #[arg(long)]
        tickets: Option<u64>,
    },
    /// Generate one or more random mnemonics.
    Generate {
        /// Number of mnemonics to generate.
        #[arg(short, long)]
        count: Option<u32>,

        /// Entropy size in bytes: 16, 20, 24, 28, or 32. Defaults to 16 (12 words).
        #[arg(short, long)]
        entropy: Option<String>,
    },
    /// Write a default config.toml to the given path.
    Config {
        #[arg(short, long, default_value = "config.toml")]
        output: String,
    },
    /// Inspect or modify the saved checkpoint.
    Checkpoint {
        #[arg(short, long)]
        file: String,

        #[command(subcommand)]
        action: CheckpointAction,
    },
    /// Compute ticket boundaries for the given ticket size.
    Ticket {
        #[arg(short, long)]
        checkpoint: String,

        #[arg(short, long)]
        ticket_size: u64,
    },
}

#[derive(Subcommand)]
enum CheckpointAction {
    Show,
    Reset,
    Resume,
}

fn main() {
    let cli = Cli::parse();

    // Detect verbose from scan subcommand for logger init
    let verbose = matches!(&cli.command, Commands::Scan { verbose: true, .. });
    ui::init_logger(verbose);
    ui::banner();

    match cli.command {
        Commands::Scan {
            mnemonic,
            target,
            prefix,
            targets,
            path,
            passphrase,
            config,
            checkpoint,
            resume,
            tickets,
            validity,
            save_every,
            export_match,
            verbose,
        } => {
            cmd_scan(
                mnemonic,
                target,
                prefix,
                targets,
                path,
                passphrase,
                config,
                checkpoint,
                resume,
                tickets,
                validity,
                save_every,
                export_match,
                verbose,
            );
        }
        Commands::Validate {
            mnemonic,
            passphrase,
            path,
        } => {
            cmd_validate(&mnemonic, &passphrase, &path);
        }
        Commands::Check {
            mnemonic,
            mnemonics_file,
            target,
            prefix,
            targets_file,
            passphrase,
            path,
            stop_on_first_match,
            quiet,
            random,
            max_attempts,
            checkpoint,
            resume,
            threads,
            words,
            random_shuffles,
            tickets,
        } => {
            let exit = cmd_check(
                mnemonic,
                mnemonics_file,
                target,
                prefix,
                targets_file,
                passphrase,
                path,
                stop_on_first_match,
                quiet,
                random,
                max_attempts,
                checkpoint,
                resume,
                threads,
                words,
                random_shuffles,
                tickets,
            );
            if exit != 0 {
                std::process::exit(exit);
            }
        }
        Commands::Generate { count, entropy } => {
            cmd_generate(count, entropy);
        }
        Commands::Config { output } => {
            cmd_config(&output);
        }
        Commands::Checkpoint { file, action } => {
            cmd_checkpoint(&file, action);
        }
        Commands::Ticket {
            checkpoint,
            ticket_size,
        } => {
            cmd_ticket(&checkpoint, ticket_size);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum MatchMode {
    Exact,
    Prefix,
    Any,
}

struct ScanParams {
    mode: MatchMode,
    target: String,
    prefix: String,
    targets: HashSet<String>,
    path: String,
    passphrase: String,
    cp_path: String,
    ticket_size: u64,
    save_every: u64,
    export_path: Option<String>,
    verbose: bool,
}

fn resolve_target(
    target: Option<String>,
    prefix: Option<String>,
    targets_file: Option<String>,
) -> Result<ScanParamsStub, String> {
    let mut chosen = 0;
    if target.is_some() {
        chosen += 1;
    }
    if prefix.is_some() {
        chosen += 1;
    }
    if targets_file.is_some() {
        chosen += 1;
    }
    if chosen == 0 {
        return Err("One of --target, --prefix, or --targets must be supplied".into());
    }
    if chosen > 1 {
        return Err("--target, --prefix, and --targets are mutually exclusive".into());
    }
    if let Some(t) = target {
        return Ok(ScanParamsStub::Exact(t));
    }
    if let Some(p) = prefix {
        if p.is_empty() {
            return Err("--prefix cannot be empty".into());
        }
        return Ok(ScanParamsStub::Prefix(p));
    }
    let path = targets_file.unwrap();
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read targets file '{}': {}", path, e))?;
    let mut set = HashSet::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        set.insert(line.to_string());
    }
    if set.is_empty() {
        return Err(format!("Targets file '{}' contains no addresses", path));
    }
    Ok(ScanParamsStub::Any(set))
}

enum ScanParamsStub {
    Exact(String),
    Prefix(String),
    Any(HashSet<String>),
}

fn cmd_scan(
    mnemonic: Option<String>,
    target: Option<String>,
    prefix: Option<String>,
    targets_file: Option<String>,
    path: Option<String>,
    passphrase: String,
    config_path: Option<String>,
    checkpoint_path: Option<String>,
    resume: bool,
    tickets: Option<u64>,
    validity: bool,
    save_every: Option<u64>,
    export_match: Option<String>,
    verbose: bool,
) {
    if validity {
        let m = match mnemonic {
            Some(m) => m,
            None => {
                ui::error("--validity requires --mnemonic");
                return;
            }
        };
        log::info!("Validating mnemonic: {}", m);
        let words: Vec<&str> = m.split_whitespace().collect();
        match Bip39::validate(&words) {
            Ok(()) => {
                ui::success(&format!("Mnemonic is VALID: {}", m));
                let seed = Bip39::mnemonic_to_seed(&words, &passphrase).unwrap();
                log::debug!("Seed derived ({} bytes)", seed.len());
                let master = match Bip32::from_seed(&seed) {
                    Ok(m) => m,
                    Err(e) => {
                        ui::error(&format!("Failed to derive master key: {}", e));
                        return;
                    }
                };
                log::debug!("Master key derived");
                let derived = match Bip32::derive_path(&master, "m/84'/0'/0'/0/0") {
                    Ok(d) => d,
                    Err(e) => {
                        ui::error(&format!("Failed to derive path: {}", e));
                        return;
                    }
                };
                log::debug!("Path derived");
                let addr = match Bip32::privkey_to_address(&derived.key) {
                    Ok(a) => a,
                    Err(e) => {
                        ui::error(&format!("Failed to derive address: {}", e));
                        return;
                    }
                };
                ui::key_val("Address", &addr);
                match (target.as_ref(), prefix.as_ref()) {
                    (Some(t), _) if addr == *t => ui::success("MATCH FOUND"),
                    (_, Some(p)) if addr.starts_with(p.as_str()) => ui::success("MATCH FOUND"),
                    (Some(t), _) => ui::warn(&format!("Does not match target: {}", t)),
                    (_, Some(p)) => ui::warn(&format!("Does not match prefix: {}", p)),
                    _ => {}
                }
            }
            Err(e) => {
                ui::error(&format!("INVALID mnemonic: {}", e));
            }
        }
        return;
    }

    if let Some(ref m) = mnemonic {
        let words: Vec<&str> = m.split_whitespace().collect();
        if let Err(e) = Bip39::validate(&words) {
            ui::error(&format!("Invalid mnemonic: {}", e));
            std::process::exit(1);
        }
    }

    let config = if let Some(ref path) = config_path {
        Config::load(path).unwrap_or_else(|e| {
            ui::warn(&format!("Failed to load config: {}, using defaults", e));
            Config::default()
        })
    } else {
        Config::default()
    };

    let effective_path = path.unwrap_or_else(|| config.scan.derivation_path.clone());
    let effective_passphrase = if passphrase.is_empty() {
        config.scan.passphrase.clone()
    } else {
        passphrase
    };

    let resolved = match resolve_target(target.or_else(|| {
        if !config.scan.target_address.is_empty() {
            Some(config.scan.target_address.clone())
        } else {
            None
        }
    }), prefix, targets_file) {
        Ok(r) => r,
        Err(e) => {
            ui::error(&e.to_string());
            std::process::exit(2);
        }
    };

    let (mode, target_str, prefix_str, targets_set) = match resolved {
        ScanParamsStub::Exact(s) => (MatchMode::Exact, s, String::new(), HashSet::new()),
        ScanParamsStub::Prefix(s) => (MatchMode::Prefix, String::new(), s, HashSet::new()),
        ScanParamsStub::Any(s) => (MatchMode::Any, String::new(), String::new(), s),
    };

    let cp_path = checkpoint_path.unwrap_or_else(|| "checkpoint.json".to_string());
    let ticket_size = tickets.unwrap_or(1_000_000);
    let save_every = save_every.unwrap_or(config.performance.save_progress_every);

    let params = ScanParams {
        mode,
        target: target_str,
        prefix: prefix_str,
        targets: targets_set,
        path: effective_path,
        passphrase: effective_passphrase,
        cp_path: cp_path.clone(),
        ticket_size,
        save_every,
        export_path: export_match,
        verbose,
    };

    if resume {
        match Checkpoint::load(&cp_path) {
            Ok(mut cp) => {
                if matches!(cp.state, ScanState::Found) {
                    ui::success(&format!("Target already found at: {}", cp.found_address.unwrap_or_default()));
                    return;
                }
                cp.state = ScanState::Running;
                let _ = cp.save(&cp_path);
                ui::section("Resuming Scan");
                ui::key_val_u64("From index", cp.current_index);
                ui::key_val_u64("Scanned", cp.scanned_count);
                ui::key_val_u64("Total", cp.total_combinations);
                ui::key_val_f64("Progress %", cp.progress_pct());
                ui::key_val_f64("Rate /s", cp.rate());
                log::info!("Resuming from index {} ({:.2}%)", cp.current_index, cp.progress_pct());

                run_scan(&params, cp.current_index, cp.total_combinations);
            }
            Err(e) => {
                ui::warn(&format!("No checkpoint found: {}", e));
                ui::info("Starting fresh scan...");
                run_scan_fresh(&params);
            }
        }
    } else {
        run_scan_fresh(&params);
    }
}

fn run_scan_fresh(params: &ScanParams) {
    let total: u64 = 2048u64.pow(11);

    ui::section("BIP39 Scanner");
    match params.mode {
        MatchMode::Exact => ui::key_val("Target", &params.target),
        MatchMode::Prefix => ui::key_val("Prefix", &params.prefix),
        MatchMode::Any => ui::key_val_u64("Targets", params.targets.len() as u64),
    }
    ui::key_val("Path", &params.path);
    ui::key_val_u64("Combinations", total);
    ui::key_val_u64("Ticket size", params.ticket_size);
    ui::key_val_u64("Tickets", (total + params.ticket_size - 1) / params.ticket_size);
    ui::separator();

    log::info!("Starting fresh scan: total={}, ticket_size={}", total, params.ticket_size);

    let mut cp = Checkpoint::new(total);
    cp.state = ScanState::Running;
    let _ = cp.save(&params.cp_path);
    log::debug!("Initial checkpoint saved to {}", params.cp_path);

    let _tm = TicketManager::new(total, params.ticket_size);
    run_scan(params, 0, total);
}

fn run_scan(params: &ScanParams, start: u64, total: u64) {
    let num_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    let found = Arc::new(AtomicBool::new(false));
    let count = Arc::new(AtomicU64::new(start));
    let matched_addr = Arc::new(Mutex::new(None::<String>));
    let matched_mnemonic = Arc::new(Mutex::new(None::<Vec<String>>));
    let matched_index = Arc::new(AtomicU64::new(0));

    let total_tickets = (total + params.ticket_size - 1) / params.ticket_size;
    let ticket_counter = Arc::new(AtomicU64::new(0));

    let started = Instant::now();

    // Background checkpoint saver
    let cp_path = params.cp_path.clone();
    let count_clone = Arc::clone(&count);
    let found_clone = Arc::clone(&found);
    let save_handle = std::thread::spawn(move || {
        let mut last_save = 0u64;
        loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            if found_clone.load(Ordering::Relaxed) {
                break;
            }
            let current = count_clone.load(Ordering::Relaxed);
            if current > last_save + 100000 {
                let mut cp = Checkpoint::load(&cp_path)
                    .unwrap_or_else(|_| Checkpoint::new(total));
                cp.state = ScanState::Running;
                cp.update(current, current);
                let _ = cp.save(&cp_path);
                last_save = current;
            }
        }
    });

    ui::info(&format!("Starting scan with {} threads...", num_threads));

    let mut handles = Vec::with_capacity(num_threads);

    for _thread_id in 0..num_threads {
        let params = ScanParams {
            mode: params.mode,
            target: params.target.clone(),
            prefix: params.prefix.clone(),
            targets: params.targets.clone(),
            path: params.path.clone(),
            passphrase: params.passphrase.clone(),
            cp_path: params.cp_path.clone(),
            ticket_size: params.ticket_size,
            save_every: params.save_every,
            export_path: params.export_path.clone(),
            verbose: params.verbose,
        };

        let found = Arc::clone(&found);
        let count = Arc::clone(&count);
        let matched_addr = Arc::clone(&matched_addr);
        let matched_mnemonic = Arc::clone(&matched_mnemonic);
        let matched_index = Arc::clone(&matched_index);
        let ticket_counter = Arc::clone(&ticket_counter);

        let handle = std::thread::spawn(move || {
            let mut local_count: u64 = 0;
            let mut local_batch: u64 = 0;

            loop {
                if found.load(Ordering::Relaxed) {
                    break;
                }

                let ticket_id = ticket_counter.fetch_add(1, Ordering::Relaxed);
                if ticket_id >= total_tickets {
                    break;
                }

                let ticket_start = ticket_id * params.ticket_size;
                let ticket_end = std::cmp::min(ticket_start + params.ticket_size, total);

                for idx in ticket_start..ticket_end {
                    if found.load(Ordering::Relaxed) {
                        break;
                    }

                    let words = index_to_mnemonic(idx);
                    let seed = match Bip39::mnemonic_to_seed(&words, &params.passphrase) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let master = match Bip32::from_seed(&seed) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    let derived = match Bip32::derive_path(&master, &params.path) {
                        Ok(d) => d,
                        Err(_) => continue,
                    };
                    let addr = match Bip32::privkey_to_address(&derived.key) {
                        Ok(a) => a,
                        Err(_) => continue,
                    };

                    let matched = match params.mode {
                        MatchMode::Exact => addr == params.target,
                        MatchMode::Prefix => addr.starts_with(&params.prefix),
                        MatchMode::Any => params.targets.contains(&addr),
                    };

                    if matched {
                        found.store(true, Ordering::Relaxed);
                        *matched_addr.lock().unwrap() = Some(addr.clone());
                        *matched_mnemonic.lock().unwrap() = Some(words.iter().map(|s| s.to_string()).collect());
                        matched_index.store(idx, Ordering::Relaxed);
                        break;
                    }

                    local_count += 1;
                    local_batch += 1;
                    count.fetch_add(1, Ordering::Relaxed);

                    if params.verbose && local_batch % 10000 == 0 {
                        let elapsed = started.elapsed().as_secs_f64();
                        let current = count.load(Ordering::Relaxed);
                        let rate = if elapsed > 0.0 { (current - start) as f64 / elapsed } else { 0.0 };
                        ui::progress(current, 0, 0, rate);
                    }
                }
            }

            local_count
        });

        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.join();
    }

    found.store(true, Ordering::Relaxed);
    let _ = save_handle.join();

    let final_count = count.load(Ordering::Relaxed);
    let mut cp = Checkpoint::load(&params.cp_path).unwrap_or_else(|_| Checkpoint::new(total));
    let addr = matched_addr.lock().unwrap().clone();
    let mnemonic = matched_mnemonic.lock().unwrap().clone();
    let hit_index = matched_index.load(Ordering::Relaxed);

    println!();
    ui::separator();
    if found.load(Ordering::Relaxed) && addr.is_some() {
        let addr = addr.unwrap_or_default();
        let mnemonic = mnemonic.unwrap_or_default();
        ui::match_found(0, &mnemonic.join(" "), &addr);
        ui::key_val_u64("Index", hit_index);
        cp.state = ScanState::Found;
        cp.found_address = Some(addr.clone());
        cp.update(hit_index, final_count);
        log::info!("Target found at index {}: {} -> {}", hit_index, mnemonic.join(" "), addr);
        if let Some(ref path) = params.export_path {
            export_hit(path, &mnemonic, &addr, hit_index);
        }
    } else {
        ui::info("Scan complete. Target not found.");
        ui::key_val_u64("Total scanned", final_count);
        cp.state = ScanState::Completed;
        cp.update(final_count, final_count);
    }
    ui::separator();
    let _ = cp.save(&params.cp_path);
}

fn export_hit(path: &str, mnemonic: &[String], addr: &str, index: u64) {
    let line = format!(
        "{}\t{}\t{}\t{}\n",
        now_secs(),
        index,
        mnemonic.join(" "),
        addr
    );
    let mut file = match OpenOptions::new().create(true).append(true).open(path) {
        Ok(f) => f,
        Err(e) => {
            ui::error(&format!("Failed to open export file '{}': {}", path, e));
            return;
        }
    };
    if let Err(e) = file.write_all(line.as_bytes()) {
        ui::error(&format!("Failed to write export: {}", e));
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn index_to_mnemonic(index: u64) -> Vec<&'static str> {
    let mut words = Vec::with_capacity(12);

    for i in 0..12 {
        let idx = ((index >> (132 - (i + 1) * 11)) & 0x7FF) as u16;
        words.push(Bip39::index_to_word(idx).unwrap());
    }

    words
}

fn cmd_validate(mnemonic: &str, passphrase: &str, path: &str) {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();

    ui::section("Validate Mnemonic");
    ui::key_val("Mnemonic", mnemonic);
    ui::key_val_u64("Word count", words.len() as u64);
    log::info!("Validating mnemonic with {} words", words.len());

    let (valid, total, invalid) = Bip39::validate_partial(&words);
    ui::key_val(&format!("Valid words"), &format!("{}/{}", valid, total));

    if !invalid.is_empty() {
        ui::warn(&format!("Invalid words: {:?}", invalid));
    }

    match Bip39::validate(&words) {
        Ok(()) => {
            ui::success("Result: VALID");
            log::debug!("Mnemonic validated, deriving seed...");
            let seed = Bip39::mnemonic_to_seed(&words, passphrase).unwrap();
            log::debug!("Seed derived ({} bytes)", seed.len());
            let master = match Bip32::from_seed(&seed) {
                Ok(m) => m,
                Err(e) => {
                    ui::error(&format!("Failed to derive master key: {}", e));
                    return;
                }
            };
            let derived = match Bip32::derive_path(&master, path) {
                Ok(d) => d,
                Err(e) => {
                    ui::error(&format!("Failed to derive path: {}", e));
                    return;
                }
            };
            let addr = match Bip32::privkey_to_address(&derived.key) {
                Ok(a) => a,
                Err(e) => {
                    ui::error(&format!("Failed to derive address: {}", e));
                    return;
                }
            };
            ui::separator();
            ui::key_val("First address", &addr);
            ui::key_val("Path", path);
        }
        Err(e) => {
            ui::error(&format!("Result: INVALID - {}", e));
        }
    }
}

fn factorial(n: usize) -> u64 {
    (1..=n as u64).product()
}

/// Generate all permutations of `words` and send each valid-BIP39 permutation
/// into the channel. Returns the total number of permutations generated.
fn send_permutations(
    tx: &mpsc::Sender<CheckWorkItem>,
    words: &mut [String],
    start: usize,
) -> u64 {
    if start == words.len() - 1 {
        let phrase = words.join(" ");
        let word_refs: Vec<&str> = words.iter().map(|s| s.as_str()).collect();
        if Bip39::validate(&word_refs).is_ok() {
            let _ = tx.send(CheckWorkItem::Mnemonic(phrase));
        }
        return 1;
    }
    let mut count = 0u64;
    for i in start..words.len() {
        words.swap(start, i);
        count += send_permutations(tx, words, start + 1);
        words.swap(start, i);
    }
    count
}

fn cmd_check_permutations(
    words: &[String],
    target: Option<String>,
    prefix: Option<String>,
    targets_file: Option<String>,
    passphrase: String,
    path: String,
    stop_on_first_match: bool,
    quiet: bool,
    checkpoint_path: Option<String>,
    resume: bool,
    threads: Option<usize>,
    random_count: Option<u64>,
    num_tickets: Option<u64>,
) -> i32 {
    if words.len() != 12 {
        ui::error(&format!("--words requires exactly 12 words, got {}", words.len()));
        return 2;
    }

    for w in words {
        if !Bip39::is_valid_word(w) {
            ui::error(&format!("Unknown BIP39 word: {}", w));
            return 2;
        }
    }

    let mut chosen = 0;
    if target.is_some() { chosen += 1; }
    if prefix.is_some() { chosen += 1; }
    if targets_file.is_some() { chosen += 1; }
    if chosen == 0 {
        ui::error("One of --target, --prefix, or --targets-file must be supplied");
        return 2;
    }
    if chosen > 1 {
        ui::error("--target, --prefix, and --targets-file are mutually exclusive");
        return 2;
    }

    let mode: u8 = if target.is_some() { 0 } else if prefix.is_some() { 1 } else { 2 };
    let exact_target = target.unwrap_or_default();
    let vanity_prefix = prefix.unwrap_or_default();
    let batch_targets: HashSet<String> = if let Some(ref p) = targets_file {
        match std::fs::read_to_string(p) {
            Ok(content) => content.lines().map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#')).collect(),
            Err(e) => { ui::error(&format!("Failed to read targets file: {}", e)); return 2; }
        }
    } else { HashSet::new() };

    let num_threads = threads.unwrap_or_else(|| {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
    });

    let total_perms = factorial(12);
    let is_random = random_count.is_some();
    let total_work: u64 = if is_random { random_count.unwrap_or(0) } else { total_perms };
    let ticket_size: u64 = num_tickets.map(|t| if t > 0 { (total_work + t - 1) / t } else { total_work }).unwrap_or(total_work);

    // Checkpoint load
    let mut cp_attempts_offset: u64 = 0;
    let mut cp = if let Some(ref cp_path) = checkpoint_path {
        if resume {
            match CheckCheckpoint::load(cp_path) {
                Ok(loaded) => {
                    if !quiet {
                        ui::section("Resuming from Checkpoint");
                        ui::key_val_u64("Attempts", loaded.attempts);
                        ui::key_val_u64("Checked", loaded.checked);
                    }
                    cp_attempts_offset = loaded.attempts;
                    loaded
                }
                Err(e) => { ui::warn(&format!("No checkpoint: {}. Starting fresh.", e)); CheckCheckpoint::new() }
            }
        } else { CheckCheckpoint::new() }
    } else { CheckCheckpoint::new() };

    if !quiet {
        ui::section("Permutation Check");
        ui::key_val("Words", &words.join(" "));
        match mode {
            0 => ui::key_val("Target", &exact_target),
            1 => ui::key_val("Prefix", &vanity_prefix),
            _ => ui::key_val_u64("Targets", batch_targets.len() as u64),
        }
        ui::key_val("Path", &path);
        ui::key_val_u64("Threads", num_threads as u64);
        if is_random {
            ui::key_val_u64("Random shuffles", total_work);
        } else {
            ui::key_val_u64("Total permutations", total_perms);
            ui::key_val("Estimated valid", &format!("~{:.0}", (total_perms / 16) as f64));
        }
        ui::key_val_u64("Ticket size", ticket_size);
        ui::separator();
        log::info!("Permutation mode: {} words, {} work items, ticket_size={}", words.len(), total_work, ticket_size);
    }

    let (tx, rx) = mpsc::channel::<CheckWorkItem>();
    let rx = Arc::new(Mutex::new(rx));

    if is_random {
        // Random mode: spawn N threads that each generate random shuffles
        let words_owned = words.to_vec();
        let gen_count = Arc::new(AtomicU64::new(0));
        let gen_limit = total_work;
        for _ in 0..num_threads {
            let tx = tx.clone();
            let words = words_owned.clone();
            let gen_count = Arc::clone(&gen_count);
            std::thread::spawn(move || {
                let mut local_words = words.clone();
                loop {
                    if gen_count.load(Ordering::Relaxed) >= gen_limit { break; }
                    let mut buf = [0u8; 16];
                    getrandom::fill(&mut buf).unwrap_or_default();
                    for i in (1..local_words.len()).rev() {
                        let j = u64::from_ne_bytes(buf[0..8].try_into().unwrap()) as usize % (i + 1);
                        local_words.swap(i, j);
                        getrandom::fill(&mut buf).unwrap_or_default();
                    }
                    let phrase = local_words.join(" ");
                    gen_count.fetch_add(1, Ordering::Relaxed);
                    if tx.send(CheckWorkItem::Mnemonic(phrase)).is_err() {
                        break;
                    }
                }
            });
        }
    } else {
        // Full permutation mode: generate all perms in background thread
        let tx_clone = tx.clone();
        let words_owned = words.to_vec();
        std::thread::spawn(move || {
            let mut words_copy = words_owned;
            send_permutations(&tx_clone, &mut words_copy, 0);
        });
    }
    drop(tx);

    let checked = Arc::new(AtomicU64::new(0));
    let valid_ctr = Arc::new(AtomicU64::new(0));
    let match_count = Arc::new(AtomicU64::new(0));
    let first_match = Arc::new(Mutex::new(None::<(String, String)>));
    let found = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::with_capacity(num_threads);

    for thread_id in 0..num_threads {
        let rx = Arc::clone(&rx);
        let passphrase = passphrase.clone();
        let path = path.clone();
        let exact_target = exact_target.clone();
        let vanity_prefix = vanity_prefix.clone();
        let batch_targets = batch_targets.clone();
        let checked = Arc::clone(&checked);
        let valid_ctr = Arc::clone(&valid_ctr);
        let match_count = Arc::clone(&match_count);
        let first_match = Arc::clone(&first_match);
        let found = Arc::clone(&found);

        let handle = std::thread::spawn(move || {
            loop {
                if found.load(Ordering::Relaxed) { break; }
                let work = { let rx_guard = rx.lock().unwrap(); rx_guard.try_recv() };
                match work {
                    Ok(CheckWorkItem::Mnemonic(phrase)) => {
                        let words: Vec<&str> = phrase.split_whitespace().collect();
                        checked.fetch_add(1, Ordering::Relaxed);
                        let result = check_one(&words, &passphrase, &path, mode, &exact_target, &vanity_prefix, &batch_targets, true);
                        match result {
                            CheckOutcome::Invalid => {}
                            CheckOutcome::Derived(addr) => {
                                valid_ctr.fetch_add(1, Ordering::Relaxed);
                                let matched = match mode {
                                    0 => addr == exact_target,
                                    1 => addr.starts_with(&vanity_prefix),
                                    _ => batch_targets.contains(&addr),
                                };
                                if matched {
                                    match_count.fetch_add(1, Ordering::Relaxed);
                                    let mut fm = first_match.lock().unwrap();
                                    if fm.is_none() { *fm = Some((phrase.clone(), addr.clone())); }
                                    ui::match_found(thread_id, &phrase, &addr);
                                    if stop_on_first_match { found.store(true, Ordering::Relaxed); break; }
                                }
                            }
                        }
                    }
                    Ok(CheckWorkItem::Random) => unreachable!(),
                    Err(mpsc::TryRecvError::Empty) => { std::thread::sleep(std::time::Duration::from_millis(10)); }
                    Err(mpsc::TryRecvError::Disconnected) => { break; }
                }
            }
        });
        handles.push(handle);
    }

    // Background checkpoint saver
    let cp_saver = if checkpoint_path.is_some() {
        let cp_path = checkpoint_path.clone().unwrap();
        let checked = Arc::clone(&checked);
        let valid_ctr = Arc::clone(&valid_ctr);
        let match_count = Arc::clone(&match_count);
        let first_match = Arc::clone(&first_match);
        let found = Arc::clone(&found);
        let start_time = cp.start_time;
        Some(std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
                if found.load(Ordering::Relaxed) { break; }
                let c = checked.load(Ordering::Relaxed);
                let v = valid_ctr.load(Ordering::Relaxed);
                let m = match_count.load(Ordering::Relaxed);
                let fm = first_match.lock().unwrap().clone();
                let cp = CheckCheckpoint {
                    attempts: cp_attempts_offset + c, checked: c, valid: v,
                    matches: m, found: fm, state: ScanState::Running,
                    start_time, last_update: cp_timestamp(),
                };
                let _ = cp.save(&cp_path);
            }
        }))
    } else { None };

    for handle in handles { let _ = handle.join(); }
    found.store(true, Ordering::Relaxed);
    if let Some(h) = cp_saver { let _ = h.join(); }

    let final_checked = checked.load(Ordering::Relaxed);
    let final_valid = valid_ctr.load(Ordering::Relaxed);
    let final_matches = match_count.load(Ordering::Relaxed);
    let fm = first_match.lock().unwrap().clone();

    // Final checkpoint save
    if let Some(ref cp_path) = checkpoint_path {
        cp.attempts = cp_attempts_offset + final_checked;
        cp.checked = final_checked;
        cp.valid = final_valid;
        cp.matches = final_matches;
        cp.found = fm.clone();
        cp.state = if final_matches > 0 { ScanState::Found } else { ScanState::Completed };
        cp.last_update = cp_timestamp();
        let _ = cp.save(cp_path);
    }

    if !quiet {
        ui::separator();
        if let Some((ref phrase, ref addr)) = fm {
            ui::success(&format!("First match: {} -> {}", phrase, addr));
        }
        ui::key_val_u64("Checked", final_checked);
        ui::key_val_u64("Valid", final_valid);
        ui::key_val_u64("Matches", final_matches);
        ui::separator();
    }

    if final_matches > 0 { 0 } else { 3 }
}

fn cmd_check(
    mnemonic: Option<String>,
    mnemonics_file: Option<String>,
    target: Option<String>,
    prefix: Option<String>,
    targets_file: Option<String>,
    passphrase: String,
    path: String,
    stop_on_first_match: bool,
    quiet: bool,
    random: Option<u32>,
    max_attempts: u32,
    checkpoint_path: Option<String>,
    resume: bool,
    threads: Option<usize>,
    words_arg: Option<Vec<String>>,
    random_shuffles: Option<u64>,
    tickets: Option<u64>,
) -> i32 {
    // Permutation mode: --words takes precedence
    if let Some(ref words) = words_arg {
        return cmd_check_permutations(
            words, target, prefix, targets_file,
            passphrase, path, stop_on_first_match, quiet,
            checkpoint_path, resume, threads, random_shuffles, tickets,
        );
    }

    if mnemonic.is_none() && mnemonics_file.is_none() && random.is_none() {
        ui::error("One of --mnemonic, --mnemonics-file, --random N, or --words is required");
        return 2;
    }

    let mut chosen = 0;
    if target.is_some() {
        chosen += 1;
    }
    if prefix.is_some() {
        chosen += 1;
    }
    if targets_file.is_some() {
        chosen += 1;
    }
    if chosen == 0 {
        ui::error("One of --target, --prefix, or --targets-file must be supplied");
        return 2;
    }
    if chosen > 1 {
        ui::error("--target, --prefix, and --targets-file are mutually exclusive");
        return 2;
    }

    let mode: u8 = if target.is_some() {
        0
    } else if prefix.is_some() {
        1
    } else {
        2
    };
    let exact_target = target.unwrap_or_default();
    let vanity_prefix = prefix.unwrap_or_default();
    let batch_targets: HashSet<String> = if let Some(ref p) = targets_file {
        match std::fs::read_to_string(p) {
            Ok(content) => content
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect(),
            Err(e) => {
                ui::error(&format!("Failed to read targets file '{}': {}", p, e));
                return 2;
            }
        }
    } else {
        HashSet::new()
    };

    let phrases: Vec<String> = if let Some(m) = mnemonic {
        vec![m]
    } else if let Some(p) = mnemonics_file {
        match std::fs::read_to_string(&p) {
            Ok(content) => content
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect(),
            Err(e) => {
                ui::error(&format!("Failed to read mnemonics file '{}': {}", p, e));
                return 2;
            }
        }
    } else {
        Vec::new()
    };

    let random_count = random.unwrap_or(0);

    if random_count == 0 && phrases.is_empty() {
        ui::error("No mnemonics to check");
        return 2;
    }

    let num_threads = threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    });

    // Checkpoint: load or create
    let mut cp_attempts_offset: u64 = 0;
    let mut cp = if let Some(ref cp_path) = checkpoint_path {
        if resume {
            match CheckCheckpoint::load(cp_path) {
                Ok(loaded) => {
                    if !quiet {
                        ui::section("Resuming from Checkpoint");
                        ui::key_val_u64("Attempts", loaded.attempts);
                        ui::key_val_u64("Checked", loaded.checked);
                        ui::key_val_u64("Valid", loaded.valid);
                        ui::key_val_u64("Matches", loaded.matches);
                    }
                    cp_attempts_offset = loaded.attempts;
                    loaded
                }
                Err(e) => {
                    ui::warn(&format!("Failed to load checkpoint: {}. Starting fresh.", e));
                    CheckCheckpoint::new()
                }
            }
        } else {
            CheckCheckpoint::new()
        }
    } else {
        CheckCheckpoint::new()
    };

    if !quiet {
        ui::section("Check Mnemonics");
        match mode {
            0 => ui::key_val("Target", &exact_target),
            1 => ui::key_val("Prefix", &vanity_prefix),
            _ => ui::key_val_u64("Targets", batch_targets.len() as u64),
        }
        ui::key_val("Path", &path);
        ui::key_val_u64("Threads", num_threads as u64);
        if random_count > 0 {
            ui::key_val("Mode", &format!("random ({} mnemonics)", random_count));
            if max_attempts > 0 {
                ui::key_val_u64("Max attempts", max_attempts as u64);
            }
            if checkpoint_path.is_some() {
                ui::key_val("Checkpoint", checkpoint_path.as_deref().unwrap());
            }
        } else {
            ui::key_val_u64("Phrases", phrases.len() as u64);
        }
        ui::separator();
        log::info!("Starting check: mode={}, threads={}", if random_count > 0 { "random" } else { "file" }, num_threads);
    }

    let checked = Arc::new(AtomicU64::new(0));
    let valid_count = Arc::new(AtomicU64::new(0));
    let match_count = Arc::new(AtomicU64::new(0));
    let first_match = Arc::new(Mutex::new(None::<(String, String)>));
    let found = Arc::new(AtomicBool::new(false));

    let (tx, rx) = mpsc::channel::<CheckWorkItem>();
    let rx = Arc::new(Mutex::new(rx));

    for phrase in &phrases {
        let _ = tx.send(CheckWorkItem::Mnemonic(phrase.clone()));
    }

    if random_count > 0 && !found.load(Ordering::Relaxed) {
        let gen_count = if max_attempts == 0 || max_attempts > random_count {
            random_count
        } else {
            max_attempts
        };
        for _ in 0..gen_count {
            let _ = tx.send(CheckWorkItem::Random);
        }
    }

    drop(tx);

    let mut handles = Vec::with_capacity(num_threads);

    for thread_id in 0..num_threads {
        let rx = Arc::clone(&rx);
        let passphrase = passphrase.clone();
        let path = path.clone();
        let exact_target = exact_target.clone();
        let vanity_prefix = vanity_prefix.clone();
        let batch_targets = batch_targets.clone();
        let checked = Arc::clone(&checked);
        let valid_count = Arc::clone(&valid_count);
        let match_count = Arc::clone(&match_count);
        let first_match = Arc::clone(&first_match);
        let found = Arc::clone(&found);

        let handle = std::thread::spawn(move || {
            loop {
                if found.load(Ordering::Relaxed) {
                    break;
                }

                let work = {
                    let rx_guard = rx.lock().unwrap();
                    rx_guard.try_recv()
                };

                match work {
                    Ok(work) => {
                        let phrase = match &work {
                            CheckWorkItem::Mnemonic(p) => p.clone(),
                            CheckWorkItem::Random => match random_phrase() {
                                Ok(p) => p,
                                Err(_) => continue,
                            },
                        };
                        let words: Vec<&str> = phrase.split_whitespace().collect();

                        checked.fetch_add(1, Ordering::Relaxed);

                        let result = check_one(&words, &passphrase, &path, mode, &exact_target, &vanity_prefix, &batch_targets, true);

                        match result {
                            CheckOutcome::Invalid => {}
                            CheckOutcome::Derived(addr) => {
                                valid_count.fetch_add(1, Ordering::Relaxed);
                                let matched = match mode {
                                    0 => addr == exact_target,
                                    1 => addr.starts_with(&vanity_prefix),
                                    _ => batch_targets.contains(&addr),
                                };
                                if matched {
                                    match_count.fetch_add(1, Ordering::Relaxed);
                                    let mut fm = first_match.lock().unwrap();
                                    if fm.is_none() {
                                        *fm = Some((phrase.clone(), addr.clone()));
                                    }
                                    ui::match_found(thread_id, &phrase, &addr);
                                    if stop_on_first_match {
                                        found.store(true, Ordering::Relaxed);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Err(mpsc::TryRecvError::Empty) => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        break;
                    }
                }
            }
        });

        handles.push(handle);
    }

    // Background checkpoint saver thread
    let cp_saver = if checkpoint_path.is_some() && random_count > 0 {
        let cp_path = checkpoint_path.clone().unwrap();
        let checked = Arc::clone(&checked);
        let valid_count = Arc::clone(&valid_count);
        let match_count = Arc::clone(&match_count);
        let first_match = Arc::clone(&first_match);
        let found = Arc::clone(&found);
        let cp_attempts_offset = cp_attempts_offset;
        let start_time = cp.start_time;

        Some(std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
                if found.load(Ordering::Relaxed) {
                    break;
                }
                let c = checked.load(Ordering::Relaxed);
                let v = valid_count.load(Ordering::Relaxed);
                let m = match_count.load(Ordering::Relaxed);
                let fm = first_match.lock().unwrap().clone();

                let cp = CheckCheckpoint {
                    attempts: cp_attempts_offset + c,
                    checked: c,
                    valid: v,
                    matches: m,
                    found: fm,
                    state: ScanState::Running,
                    start_time,
                    last_update: cp_timestamp(),
                };
                let _ = cp.save(&cp_path);
            }
        }))
    } else {
        None
    };

    for handle in handles {
        let _ = handle.join();
    }

    // Stop checkpoint saver
    found.store(true, Ordering::Relaxed);
    if let Some(h) = cp_saver {
        let _ = h.join();
    }

    let final_checked = checked.load(Ordering::Relaxed);
    let final_valid = valid_count.load(Ordering::Relaxed);
    let final_matches = match_count.load(Ordering::Relaxed);
    let fm = first_match.lock().unwrap().clone();

    // Final checkpoint save
    if let Some(ref cp_path) = checkpoint_path {
        cp.attempts = cp_attempts_offset + final_checked;
        cp.checked = final_checked;
        cp.valid = final_valid;
        cp.matches = final_matches;
        cp.found = fm.clone();
        cp.state = if final_matches > 0 {
            ScanState::Found
        } else {
            ScanState::Completed
        };
        cp.last_update = cp_timestamp();
        let _ = cp.save(cp_path);
    }

    if !quiet {
        ui::separator();
        if let Some((ref phrase, ref addr)) = fm {
            ui::success(&format!("First match: {} -> {}", phrase, addr));
        }
        ui::key_val_u64("Checked", final_checked);
        ui::key_val_u64("Valid", final_valid);
        ui::key_val_u64("Matches", final_matches);
        ui::separator();
        log::info!("Check complete: checked={}, valid={}, matches={}", final_checked, final_valid, final_matches);
    }

    if final_matches > 0 {
        0
    } else {
        3
    }
}

enum CheckWorkItem {
    Mnemonic(String),
    Random,
}

enum CheckOutcome {
    Invalid,
    Derived(String),
}

fn check_one(
    words: &[&str],
    passphrase: &str,
    path: &str,
    _mode: u8,
    _target: &str,
    _prefix: &str,
    _targets: &HashSet<String>,
    _quiet: bool,
) -> CheckOutcome {
    if let Err(_e) = Bip39::validate(words) {
        return CheckOutcome::Invalid;
    }
    let seed = match Bip39::mnemonic_to_seed(words, passphrase) {
        Ok(s) => s,
        Err(_e) => return CheckOutcome::Invalid,
    };
    let master = match Bip32::from_seed(&seed) {
        Ok(m) => m,
        Err(_e) => return CheckOutcome::Invalid,
    };
    let derived = match Bip32::derive_path(&master, path) {
        Ok(d) => d,
        Err(_e) => return CheckOutcome::Invalid,
    };
    match Bip32::privkey_to_address(&derived.key) {
        Ok(a) => CheckOutcome::Derived(a),
        Err(_e) => CheckOutcome::Invalid,
    }
}

fn random_phrase() -> Result<String, String> {
    let mut ent = [0u8; 16];
    fill_random(&mut ent)?;
    let words = Bip39::entropy_to_words(&ent).map_err(|e| e.to_string())?;
    Ok(words.join(" "))
}

fn cmd_generate(count: Option<u32>, entropy_arg: Option<String>) {
    let count = count.unwrap_or(1);
    let entropy_size: usize = match entropy_arg.as_deref() {
        Some(s) => match s.parse() {
            Ok(n) if [16, 20, 24, 28, 32].contains(&n) => n,
            Ok(n) => {
                ui::error(&format!(
                    "Invalid entropy size {}: must be one of 16, 20, 24, 28, 32",
                    n
                ));
                std::process::exit(2);
            }
            Err(e) => {
                ui::error(&format!("Invalid entropy size '{}': {}", s, e));
                std::process::exit(2);
            }
        },
        None => 16,
    };

    log::info!("Generating {} mnemonics (entropy: {} bytes)", count, entropy_size);
    for _ in 0..count {
        let mut ent = vec![0u8; entropy_size];
        if let Err(e) = fill_random(&mut ent) {
            ui::error(&format!("Failed to generate random bytes: {}", e));
            std::process::exit(1);
        }

        match Bip39::entropy_to_words(&ent) {
            Ok(words) => {
                println!("{}", words.join(" "));
            }
            Err(e) => {
                ui::error(&format!("Error: {}", e));
            }
        }
    }
}

fn fill_random(buf: &mut [u8]) -> Result<(), String> {
    getrandom::fill(buf).map_err(|e| format!("getrandom failed: {}", e))
}

fn cmd_config(output: &str) {
    let content = Config::default_config_file();
    std::fs::write(output, content).unwrap_or_else(|e| {
        ui::error(&format!("Failed to write config: {}", e));
        std::process::exit(1);
    });
    ui::success(&format!("Default config written to {}", output));
}

fn cmd_checkpoint(file: &str, action: CheckpointAction) {
    match action {
        CheckpointAction::Show => match Checkpoint::load(file) {
            Ok(cp) => {
                ui::section("Checkpoint Status");
                ui::key_val("State", &format!("{:?}", cp.state));
                ui::key_val_u64("Index", cp.current_index);
                ui::key_val(&format!("Scanned"), &format!("{} / {}", cp.scanned_count, cp.total_combinations));
                ui::key_val_f64("Progress %", cp.progress_pct());
                ui::key_val_f64("Rate /s", cp.rate());
                ui::key_val_u64("Elapsed (s)", cp.elapsed_seconds());
                if let Some(ref addr) = cp.found_address {
                    ui::key_val("Found", addr);
                }
            }
            Err(e) => {
                ui::error(&format!("Failed to load checkpoint: {}", e));
            }
        },
        CheckpointAction::Reset => {
            let cp = Checkpoint::new(2048u64.pow(11));
            let _ = cp.save(file);
            ui::success("Checkpoint reset");
        }
        CheckpointAction::Resume => match Checkpoint::load(file) {
            Ok(mut cp) => {
                cp.state = ScanState::Running;
                let _ = cp.save(file);
                ui::success(&format!("Checkpoint set to resume from index {}", cp.current_index));
            }
            Err(e) => {
                ui::error(&format!("Failed to load checkpoint: {}", e));
            }
        },
    }
}

fn cmd_ticket(checkpoint_path: &str, ticket_size: u64) {
    let total: u64 = 2048u64.pow(11);
    let tm = TicketManager::new(total, ticket_size);

    ui::section("Ticket Manager");
    ui::key_val_u64("Total", total);
    ui::key_val_u64("Ticket size", ticket_size);
    ui::key_val_u64("Tickets", tm.tickets.len() as u64);
    ui::separator();

    let ticket_file = format!("{}.tickets", checkpoint_path);
    if let Ok(_) = tm.save(&ticket_file) {
        ui::success(&format!("Tickets saved to {}", ticket_file));
    }
}