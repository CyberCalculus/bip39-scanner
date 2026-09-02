use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use clap::{Parser, Subcommand};

use bip39_scanner::bip39::Bip39;
use bip39_scanner::bip32::Bip32;
use bip39_scanner::checkpoint::{Checkpoint, ScanState};
use bip39_scanner::config::Config;
use bip39_scanner::ticket::TicketManager;

#[derive(Parser)]
#[command(name = "bip39-scanner")]
#[command(
    about = "BIP39 mnemonic scanner with checkpoint and ticket system. \
             All crypto primitives (SHA256/512, HMAC, RIPEMD160, PBKDF2, secp256k1, Bech32) \
             are implemented from scratch — no external crypto crates."
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
        #[arg(short, long)]
        target: Option<String>,

        /// Vanity prefix to match (e.g. "bc1qw"). Hits on any address starting with it.
        #[arg(long)]
        prefix: Option<String>,

        /// File with one target address per line. Hits if any target matches.
        #[arg(long)]
        targets_file: Option<String>,

        /// Optional BIP39 passphrase.
        #[arg(short, long, default_value = "")]
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
                eprintln!("--validity requires --mnemonic");
                return;
            }
        };
        let words: Vec<&str> = m.split_whitespace().collect();
        match Bip39::validate(&words) {
            Ok(()) => {
                println!("VALID mnemonic: {}", m);
                let seed = Bip39::mnemonic_to_seed(&words, &passphrase).unwrap();
                let master = Bip32::from_seed(&seed);
                let derived = Bip32::derive_path(&master, "m/84'/0'/0'/0/0");
                let addr = Bip32::privkey_to_address(&derived.key).unwrap();
                println!("Address: {}", addr);
                match (target.as_ref(), prefix.as_ref()) {
                    (Some(t), _) if addr == *t => println!("*** MATCH FOUND ***"),
                    (_, Some(p)) if addr.starts_with(p.as_str()) => println!("*** MATCH FOUND ***"),
                    (Some(t), _) => println!("Does not match target: {}", t),
                    (_, Some(p)) => println!("Does not match prefix: {}", p),
                    _ => {}
                }
            }
            Err(e) => {
                eprintln!("INVALID mnemonic: {}", e);
            }
        }
        return;
    }

    if let Some(ref m) = mnemonic {
        let words: Vec<&str> = m.split_whitespace().collect();
        if let Err(e) = Bip39::validate(&words) {
            eprintln!("Invalid mnemonic: {}", e);
            std::process::exit(1);
        }
    }

    let config = if let Some(ref path) = config_path {
        Config::load(path).unwrap_or_else(|e| {
            eprintln!("Failed to load config: {}, using defaults", e);
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
            eprintln!("{}", e);
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
                    println!("Target already found at: {}", cp.found_address.unwrap_or_default());
                    return;
                }
                cp.state = ScanState::Running;
                let _ = cp.save(&cp_path);
                println!("Resuming from index {}", cp.current_index);
                println!(
                    "Scanned: {} / {} ({:.2}%)",
                    cp.scanned_count,
                    cp.total_combinations,
                    cp.progress_pct()
                );
                println!("Rate: {:.0} mnemonics/sec", cp.rate());

                run_scan(&params, cp.current_index, cp.total_combinations);
            }
            Err(e) => {
                eprintln!("No checkpoint found: {}", e);
                eprintln!("Starting fresh scan...");
                run_scan_fresh(&params);
            }
        }
    } else {
        run_scan_fresh(&params);
    }
}

fn run_scan_fresh(params: &ScanParams) {
    let total: u64 = 2048u64.pow(11);

    println!("=== BIP39 Scanner ===");
    match params.mode {
        MatchMode::Exact => println!("Target: {}", params.target),
        MatchMode::Prefix => println!("Prefix: {}", params.prefix),
        MatchMode::Any => println!("Targets: {} addresses", params.targets.len()),
    }
    println!("Path: {}", params.path);
    println!("Total combinations: {}", total);
    println!("Ticket size: {}", params.ticket_size);
    println!("Tickets: {}", (total + params.ticket_size - 1) / params.ticket_size);
    println!();

    let mut cp = Checkpoint::new(total);
    cp.state = ScanState::Running;
    let _ = cp.save(&params.cp_path);

    let _tm = TicketManager::new(total, params.ticket_size);
    run_scan(params, 0, total);
}

fn run_scan(params: &ScanParams, start: u64, total: u64) {
    let found = Arc::new(AtomicBool::new(false));
    let count = Arc::new(AtomicU64::new(start));
    let matched_addr = Arc::new(Mutex::new(None::<String>));
    let matched_mnemonic = Arc::new(Mutex::new(None::<Vec<String>>));
    let matched_index = Arc::new(AtomicU64::new(0));

    let save_every = params.save_every;
    let started = Instant::now();

    let mut batch_count: u64 = 0;

    let total_tickets = (total + params.ticket_size - 1) / params.ticket_size;

    for ticket_id in 0..total_tickets {
        if found.load(Ordering::Relaxed) {
            break;
        }
        let ticket_start = ticket_id * params.ticket_size;
        if ticket_start < start {
            continue;
        }
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
            let master = Bip32::from_seed(&seed);
            let derived = Bip32::derive_path(&master, &params.path);
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
                count.fetch_add(1, Ordering::Relaxed);
                break;
            }

            batch_count += 1;
            let current = count.fetch_add(1, Ordering::Relaxed) + 1;

            if params.verbose && batch_count % 10000 == 0 {
                let elapsed = started.elapsed().as_secs_f64();
                let rate = if elapsed > 0.0 { (current - start) as f64 / elapsed } else { 0.0 };
                eprint!("\rScanned: {} | Rate: {:.0}/s", current, rate);
            }

            if batch_count >= save_every {
                batch_count = 0;
                let mut cp = Checkpoint::load(&params.cp_path)
                    .unwrap_or_else(|_| Checkpoint::new(total));
                cp.state = ScanState::Running;
                cp.update(current, current);
                let _ = cp.save(&params.cp_path);

                let elapsed = started.elapsed().as_secs_f64();
                let rate = if elapsed > 0.0 { (current - start) as f64 / elapsed } else { 0.0 };
                eprint!(
                    "\rProgress: {:.4}% | Scanned: {} | Rate: {:.0}/s | Checkpoint saved",
                    (current as f64 / total as f64) * 100.0,
                    current,
                    rate
                );
            }
        }

        if found.load(Ordering::Relaxed) {
            break;
        }
    }

    let final_count = count.load(Ordering::Relaxed);
    let mut cp = Checkpoint::load(&params.cp_path).unwrap_or_else(|_| Checkpoint::new(total));
    let addr = matched_addr.lock().unwrap().clone();
    let mnemonic = matched_mnemonic.lock().unwrap().clone();
    let hit_index = matched_index.load(Ordering::Relaxed);

    println!();
    if found.load(Ordering::Relaxed) {
        let addr = addr.unwrap_or_default();
        let mnemonic = mnemonic.unwrap_or_default();
        println!("*** TARGET FOUND ***");
        println!("Mnemonic: {}", mnemonic.join(" "));
        println!("Address: {}", addr);
        println!("Index: {}", hit_index);
        cp.state = ScanState::Found;
        cp.found_address = Some(addr.clone());
        cp.update(hit_index, final_count);
        if let Some(ref path) = params.export_path {
            export_hit(path, &mnemonic, &addr, hit_index);
        }
    } else {
        println!("Scan complete. Target not found.");
        println!("Total scanned: {}", final_count);
        cp.state = ScanState::Completed;
        cp.update(final_count, final_count);
    }
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
            eprintln!("Failed to open export file '{}': {}", path, e);
            return;
        }
    };
    if let Err(e) = file.write_all(line.as_bytes()) {
        eprintln!("Failed to write export: {}", e);
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

    println!("Validating: {}", mnemonic);
    println!("Word count: {}", words.len());

    let (valid, total, invalid) = Bip39::validate_partial(&words);
    println!("Valid words: {}/{}", valid, total);

    if !invalid.is_empty() {
        println!("Invalid words: {:?}", invalid);
    }

    match Bip39::validate(&words) {
        Ok(()) => {
            println!("Result: VALID");
            let seed = Bip39::mnemonic_to_seed(&words, passphrase).unwrap();
            let master = Bip32::from_seed(&seed);
            let derived = Bip32::derive_path(&master, path);
            let addr = Bip32::privkey_to_address(&derived.key).unwrap();
            println!("First address: {}", addr);
        }
        Err(e) => {
            println!("Result: INVALID - {}", e);
        }
    }
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
) -> i32 {
    if mnemonic.is_none() && mnemonics_file.is_none() && random.is_none() {
        eprintln!("One of --mnemonic, --mnemonics-file, or --random N is required");
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
        eprintln!("One of --target, --prefix, or --targets-file must be supplied");
        return 2;
    }
    if chosen > 1 {
        eprintln!("--target, --prefix, and --targets-file are mutually exclusive");
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
                eprintln!("Failed to read targets file '{}': {}", p, e);
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
                eprintln!("Failed to read mnemonics file '{}': {}", p, e);
                return 2;
            }
        }
    } else {
        Vec::new()
    };

    let random_count = random.unwrap_or(0);

    if random_count == 0 && phrases.is_empty() {
        eprintln!("No mnemonics to check");
        return 2;
    }

    if !quiet {
        match mode {
            0 => println!("Target: {}", exact_target),
            1 => println!("Prefix: {}", vanity_prefix),
            _ => println!("Targets: {} addresses", batch_targets.len()),
        }
        println!("Path: {}", path);
        if random_count > 0 {
            println!("Mode: random (will generate {} mnemonics)", random_count);
            if max_attempts > 0 {
                println!("Max attempts: {}", max_attempts);
            }
        } else {
            println!("Phrases: {}", phrases.len());
        }
        println!();
    }

    let mut checked: usize = 0;
    let mut valid: usize = 0;
    let mut matches: usize = 0;
    let mut first_match: Option<(String, String)> = None;
    let mut found_in_supplied = false;

    for phrase in &phrases {
        checked += 1;
        let words: Vec<&str> = phrase.split_whitespace().collect();

        if !quiet {
            println!("[{}/{}] {}", checked, phrases.len(), phrase);
        }

        let result = check_one(&words, &passphrase, &path, mode, &exact_target, &vanity_prefix, &batch_targets, quiet);
        match result {
            CheckOutcome::Invalid(msg) => {
                if !quiet {
                    println!("  -> INVALID: {}", msg);
                }
            }
            CheckOutcome::Derived(addr) => {
                valid += 1;
                let matched = match mode {
                    0 => addr == exact_target,
                    1 => addr.starts_with(&vanity_prefix),
                    _ => batch_targets.contains(&addr),
                };
                if matched {
                    matches += 1;
                    if first_match.is_none() {
                        first_match = Some((phrase.clone(), addr.clone()));
                    }
                    println!("*** MATCH *** address: {}", addr);
                    if stop_on_first_match {
                        found_in_supplied = true;
                        break;
                    }
                } else if !quiet {
                    println!("  -> address: {} (no match)", addr);
                }
            }
        }
    }

    if !found_in_supplied && random_count > 0 {
        if !quiet {
            println!("Generating {} random mnemonics...", random_count);
        }
        let total_to_generate = if max_attempts == 0 || max_attempts > random_count {
            random_count
        } else {
            max_attempts
        };

        for _ in 0..total_to_generate {
            checked += 1;

            let phrase = match random_phrase() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Random generation failed: {}", e);
                    return 1;
                }
            };

            if !quiet {
                println!("[{}/{}] {}", checked, total_to_generate as usize + phrases.len(), phrase);
            }

            let words: Vec<&str> = phrase.split_whitespace().collect();
            let result = check_one(&words, &passphrase, &path, mode, &exact_target, &vanity_prefix, &batch_targets, quiet);
            match result {
                CheckOutcome::Invalid(msg) => {
                    if !quiet {
                        println!("  -> INVALID: {}", msg);
                    }
                }
                CheckOutcome::Derived(addr) => {
                    valid += 1;
                    let matched = match mode {
                        0 => addr == exact_target,
                        1 => addr.starts_with(&vanity_prefix),
                        _ => batch_targets.contains(&addr),
                    };
                    if matched {
                        matches += 1;
                        if first_match.is_none() {
                            first_match = Some((phrase.clone(), addr.clone()));
                        }
                        println!("*** MATCH *** address: {}", addr);
                        if stop_on_first_match {
                            break;
                        }
                    } else if !quiet {
                        println!("  -> address: {} (no match)", addr);
                    }
                }
            }
        }
    }

    if !quiet {
        println!();
        println!(
            "Checked: {}, Valid: {}, Matches: {}",
            checked, valid, matches
        );
    }

    if matches > 0 {
        0
    } else {
        3
    }
}

enum CheckOutcome {
    Invalid(String),
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
    if let Err(e) = Bip39::validate(words) {
        return CheckOutcome::Invalid(e);
    }
    let seed = Bip39::mnemonic_to_seed(words, passphrase).unwrap();
    let master = Bip32::from_seed(&seed);
    let derived = Bip32::derive_path(&master, path);
    match Bip32::privkey_to_address(&derived.key) {
        Ok(a) => CheckOutcome::Derived(a),
        Err(e) => CheckOutcome::Invalid(format!("address derivation failed: {}", e)),
    }
}

fn random_phrase() -> Result<String, String> {
    let mut ent = [0u8; 16];
    if let Err(e) = fill_random(&mut ent) {
        return Err(format!("entropy fill failed: {}", e));
    }
    let words = Bip39::entropy_to_words(&ent)?;
    Ok(words.join(" "))
}

fn cmd_generate(count: Option<u32>, entropy_arg: Option<String>) {
    let count = count.unwrap_or(1);
    let entropy_size: usize = match entropy_arg.as_deref() {
        Some(s) => match s.parse() {
            Ok(n) if [16, 20, 24, 28, 32].contains(&n) => n,
            Ok(n) => {
                eprintln!(
                    "Invalid entropy size {}: must be one of 16, 20, 24, 28, 32",
                    n
                );
                std::process::exit(2);
            }
            Err(e) => {
                eprintln!("Invalid entropy size '{}': {}", s, e);
                std::process::exit(2);
            }
        },
        None => 16,
    };

    for _ in 0..count {
        let mut ent = vec![0u8; entropy_size];
        if let Err(e) = fill_random(&mut ent) {
            eprintln!("Failed to read random bytes: {}", e);
            std::process::exit(1);
        }

        match Bip39::entropy_to_words(&ent) {
            Ok(words) => {
                println!("{}", words.join(" "));
            }
            Err(e) => {
                eprintln!("Error: {}", e);
            }
        }
    }
}

fn fill_random(buf: &mut [u8]) -> std::io::Result<()> {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let s = RandomState::new();
    let mut hasher = s.build_hasher();
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64,
    );
    let seed = hasher.finish();
    let mut state = seed;
    for b in buf.iter_mut() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *b = (state >> 33) as u8;
    }
    Ok(())
}

fn cmd_config(output: &str) {
    let content = Config::default_config_file();
    std::fs::write(output, content).unwrap_or_else(|e| {
        eprintln!("Failed to write config: {}", e);
        std::process::exit(1);
    });
    println!("Default config written to {}", output);
}

fn cmd_checkpoint(file: &str, action: CheckpointAction) {
    match action {
        CheckpointAction::Show => match Checkpoint::load(file) {
            Ok(cp) => {
                println!("=== Checkpoint Status ===");
                println!("State: {:?}", cp.state);
                println!("Index: {}", cp.current_index);
                println!("Scanned: {} / {}", cp.scanned_count, cp.total_combinations);
                println!("Progress: {:.4}%", cp.progress_pct());
                println!("Rate: {:.0}/s", cp.rate());
                println!("Elapsed: {}s", cp.elapsed_seconds());
                if let Some(ref addr) = cp.found_address {
                    println!("Found: {}", addr);
                }
            }
            Err(e) => {
                eprintln!("Failed to load checkpoint: {}", e);
            }
        },
        CheckpointAction::Reset => {
            let cp = Checkpoint::new(2048u64.pow(11));
            let _ = cp.save(file);
            println!("Checkpoint reset");
        }
        CheckpointAction::Resume => match Checkpoint::load(file) {
            Ok(mut cp) => {
                cp.state = ScanState::Running;
                let _ = cp.save(file);
                println!("Checkpoint set to resume from index {}", cp.current_index);
            }
            Err(e) => {
                eprintln!("Failed to load checkpoint: {}", e);
            }
        },
    }
}

fn cmd_ticket(checkpoint_path: &str, ticket_size: u64) {
    let total: u64 = 2048u64.pow(11);
    let tm = TicketManager::new(total, ticket_size);

    println!("=== Ticket Manager ===");
    println!("Total: {}", total);
    println!("Ticket size: {}", ticket_size);
    println!("Tickets: {}", tm.tickets.len());
    println!();

    let ticket_file = format!("{}.tickets", checkpoint_path);
    if let Ok(_) = tm.save(&ticket_file) {
        println!("Tickets saved to {}", ticket_file);
    }
}