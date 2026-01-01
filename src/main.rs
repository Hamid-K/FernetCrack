use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, IsTerminal};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE;
use base64::Engine as _;
use clap::{Parser, Subcommand};
use crossbeam_channel::{Receiver, Sender};
use crossterm::event::{self, Event, KeyCode};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use fernet::Fernet;
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};

#[derive(Parser, Debug)]
#[command(name = "fernet-cracker")]
#[command(about = "Generic Fernet cracker with wordlist and mask modes")]
struct Args {
    /// Fernet token or path to a file containing the token
    #[arg(long)]
    token: String,

    /// Output file for decrypted plaintext (optional)
    #[arg(long)]
    out: Option<PathBuf>,

    /// Number of worker threads (defaults to CPU count)
    #[arg(long)]
    threads: Option<usize>,

    /// State file for pause/resume
    #[arg(long)]
    state: Option<PathBuf>,

    /// Resume from state file (if present)
    #[arg(long)]
    resume: bool,

    /// Disable interactive controls (p=pause/resume, q=quit)
    #[arg(long)]
    no_input: bool,

    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand, Debug)]
enum Mode {
    /// Crack using a wordlist
    Wordlist {
        /// Path to dictionary file
        path: PathBuf,
    },
    /// Crack using a hashcat-style mask (e.g. ?d?d?d?d)
    Mask {
        /// Mask string
        /// Sets: ?l/?L lower, ?u/?U upper, ?d/?D digits, ?m/?M mixed, ?h/?H alnum, ?s symbols, ?a/?A all, ?? literal ?
        mask: String,
    },
    /// Pure brute-force with a charset and min/max length
    Bruteforce {
        /// Charset (supports ?d, ?l, ?u, ?m, ?h, ?s, ?a or literal chars)
        charset: String,
        /// Minimum length
        min: usize,
        /// Maximum length
        max: usize,
    },
}

#[derive(Debug, Clone)]
struct Found {
    passphrase: String,
    plaintext: Vec<u8>,
}

fn derive_key(passphrase: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    let digest = hasher.finalize();
    URL_SAFE.encode(digest)
}

fn load_token(token_arg: &str) -> io::Result<String> {
    let path = Path::new(token_arg);
    if path.is_file() {
        Ok(fs::read_to_string(path)?.trim().to_string())
    } else {
        Ok(token_arg.trim().to_string())
    }
}

fn read_state(state_path: &Option<PathBuf>) -> u64 {
    if let Some(path) = state_path {
        if let Ok(s) = fs::read_to_string(path) {
            if let Ok(v) = s.trim().parse::<u64>() {
                return v;
            }
        }
    }
    0
}

fn write_state(state_path: &Option<PathBuf>, tested: u64) {
    if let Some(path) = state_path {
        let _ = fs::write(path, tested.to_string());
    }
}

fn worker(
    token: String,
    found: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    rx: Receiver<String>,
    tested: Arc<AtomicU64>,
    result: Arc<Mutex<Option<Found>>>,
) {
    while !stop.load(Ordering::Relaxed) {
        let passphrase = match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(p) => p,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        };
        if found.load(Ordering::Relaxed) {
            break;
        }
        let key = derive_key(&passphrase);
        if let Some(f) = Fernet::new(&key) {
            if let Ok(plaintext) = f.decrypt(&token) {
                found.store(true, Ordering::Relaxed);
                let mut lock = result.lock().unwrap();
                *lock = Some(Found { passphrase, plaintext });
                break;
            }
        }
        tested.fetch_add(1, Ordering::Relaxed);
    }
}

fn spawn_input_thread(paused: Arc<AtomicBool>, stop: Arc<AtomicBool>) -> Option<thread::JoinHandle<()>> {
    if !io::stdin().is_terminal() {
        return None;
    }
    let handle = thread::spawn(move || {
        if enable_raw_mode().is_err() {
            return;
        }
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            if event::poll(Duration::from_millis(200)).unwrap_or(false) {
                if let Ok(Event::Key(key)) = event::read() {
                    match key.code {
                        KeyCode::Char('p') => {
                            let new_state = !paused.load(Ordering::Relaxed);
                            paused.store(new_state, Ordering::Relaxed);
                        }
                        KeyCode::Char('q') => {
                            stop.store(true, Ordering::Relaxed);
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
        let _ = disable_raw_mode();
    });
    Some(handle)
}

fn parse_charset(spec: &str) -> Vec<char> {
    let mut out = Vec::new();
    let mut chars = spec.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '?' {
            let n = chars.next().unwrap_or('?');
            match n {
                'd' | 'D' => out.extend("0123456789".chars()),
                'l' | 'L' => out.extend("abcdefghijklmnopqrstuvwxyz".chars()),
                'u' | 'U' => out.extend("ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars()),
                'm' | 'M' => {
                    out.extend("abcdefghijklmnopqrstuvwxyz".chars());
                    out.extend("ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars());
                }
                'h' | 'H' => {
                    out.extend("abcdefghijklmnopqrstuvwxyz".chars());
                    out.extend("ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars());
                    out.extend("0123456789".chars());
                }
                's' => out.extend(" !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~".chars()),
                'a' | 'A' => {
                    out.extend("abcdefghijklmnopqrstuvwxyz".chars());
                    out.extend("ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars());
                    out.extend("0123456789".chars());
                    out.extend(" !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~".chars());
                }
                '?' => out.push('?'),
                other => out.push(other),
            }
        } else {
            out.push(c);
        }
    }
    out.sort();
    out.dedup();
    out
}

fn parse_mask(mask: &str) -> Vec<Vec<char>> {
    let mut sets = Vec::new();
    let mut chars = mask.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '?' {
            let n = chars.next().unwrap_or('?');
            let set: Vec<char> = match n {
                'd' | 'D' => "0123456789".chars().collect(),
                'l' | 'L' => "abcdefghijklmnopqrstuvwxyz".chars().collect(),
                'u' | 'U' => "ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect(),
                // mixed-case letters
                'm' | 'M' => {
                    let mut v = Vec::new();
                    v.extend("abcdefghijklmnopqrstuvwxyz".chars());
                    v.extend("ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars());
                    v
                }
                // alnum (lower+upper+digits)
                'h' | 'H' => {
                    let mut v = Vec::new();
                    v.extend("abcdefghijklmnopqrstuvwxyz".chars());
                    v.extend("ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars());
                    v.extend("0123456789".chars());
                    v
                }
                's' => " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~".chars().collect(),
                'a' | 'A' => {
                    let mut v = Vec::new();
                    v.extend("abcdefghijklmnopqrstuvwxyz".chars());
                    v.extend("ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars());
                    v.extend("0123456789".chars());
                    v.extend(" !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~".chars());
                    v
                }
                '?' => vec!['?'],
                other => vec![other],
            };
            sets.push(set);
        } else {
            sets.push(vec![c]);
        }
    }
    sets
}

fn total_combinations(sets: &[Vec<char>]) -> u128 {
    let mut total: u128 = 1;
    for s in sets {
        total = total.saturating_mul(s.len() as u128);
    }
    total
}

fn index_to_candidate(sets: &[Vec<char>], mut index: u128) -> String {
    let mut out = vec![' '; sets.len()];
    for i in (0..sets.len()).rev() {
        let set = &sets[i];
        let base = set.len() as u128;
        let pos = (index % base) as usize;
        out[i] = set[pos];
        index /= base;
    }
    out.into_iter().collect()
}

fn send_candidate(tx: &Sender<String>, cand: String) -> bool {
    tx.send(cand).is_ok()
}

fn run_wordlist(
    path: &Path,
    tx: Sender<String>,
    found: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    resume_from: u64,
) -> io::Result<u64> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut sent: u64 = 0;
    for (idx, line) in reader.lines().enumerate() {
        if stop.load(Ordering::Relaxed) || found.load(Ordering::Relaxed) {
            break;
        }
        while paused.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(200));
        }
        let idx = idx as u64;
        if idx < resume_from {
            continue;
        }
        let passphrase = line.unwrap_or_default();
        if passphrase.is_empty() {
            sent += 1;
            continue;
        }
        if !send_candidate(&tx, passphrase) {
            break;
        }
        sent += 1;
    }
    Ok(sent)
}

fn run_mask(
    mask: &str,
    tx: Sender<String>,
    found: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    resume_from: u64,
) -> u128 {
    let sets = parse_mask(mask);
    let total = total_combinations(&sets);
    let mut idx: u128 = resume_from as u128;
    while idx < total {
        if stop.load(Ordering::Relaxed) || found.load(Ordering::Relaxed) {
            break;
        }
        while paused.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(200));
        }
        let cand = index_to_candidate(&sets, idx);
        if !send_candidate(&tx, cand) {
            break;
        }
        idx += 1;
    }
    total
}

fn run_bruteforce(
    charset: &str,
    min: usize,
    max: usize,
    tx: Sender<String>,
    found: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    resume_from: u64,
) -> u128 {
    let set = parse_charset(charset);
    let base = set.len() as u128;
    let mut total: u128 = 0;
    for len in min..=max {
        total = total.saturating_add(base.saturating_pow(len as u32));
    }

    let mut index: u128 = resume_from as u128;
    for len in min..=max {
        let count = base.saturating_pow(len as u32);
        if index >= count {
            index -= count;
            continue;
        }
        let mut idx = index;
        while idx < count {
            if stop.load(Ordering::Relaxed) || found.load(Ordering::Relaxed) {
                return total;
            }
            while paused.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(200));
            }
            let mut out = vec![' '; len];
            let mut n = idx;
            for i in (0..len).rev() {
                let pos = (n % base) as usize;
                out[i] = set[pos];
                n /= base;
            }
            let cand: String = out.into_iter().collect();
            if !send_candidate(&tx, cand) {
                return total;
            }
            idx += 1;
        }
        index = 0;
    }
    total
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    let token = load_token(&args.token)?;

    let threads = args.threads.unwrap_or_else(|| num_cpus::get().max(2));

    let found = Arc::new(AtomicBool::new(false));
    let paused = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let tested = Arc::new(AtomicU64::new(0));
    let result: Arc<Mutex<Option<Found>>> = Arc::new(Mutex::new(None));

    let resume_from = if args.resume { read_state(&args.state) } else { 0 };
    tested.store(resume_from, Ordering::Relaxed);

    ctrlc::set_handler({
        let stop = Arc::clone(&stop);
        let tested = Arc::clone(&tested);
        let state = args.state.clone();
        move || {
            stop.store(true, Ordering::Relaxed);
            let pos = tested.load(Ordering::Relaxed);
            write_state(&state, pos);
            eprintln!("stopping... saved progress at {}", pos);
        }
    })
    .expect("failed to set Ctrl-C handler");

    let input_handle = if args.no_input { None } else { spawn_input_thread(Arc::clone(&paused), Arc::clone(&stop)) };

    let (tx, rx) = crossbeam_channel::unbounded::<String>();

    let mut handles = Vec::new();
    for _ in 0..threads {
        let rx = rx.clone();
        let token = token.clone();
        let found = Arc::clone(&found);
        let tested = Arc::clone(&tested);
        let stop = Arc::clone(&stop);
        let result = Arc::clone(&result);
        handles.push(thread::spawn(move || worker(token, found, stop, rx, tested, result)));
    }

    let total = match &args.mode {
        Mode::Wordlist { path } => {
            let file = File::open(path)?;
            let reader = BufReader::new(file);
            reader.lines().count() as u128
        }
        Mode::Mask { mask } => total_combinations(&parse_mask(mask)),
        Mode::Bruteforce { charset, min, max } => {
            let set = parse_charset(charset);
            if set.is_empty() {
                eprintln!("Charset resolved to empty set");
                std::process::exit(2);
            }
            let base = set.len() as u128;
            let mut t: u128 = 0;
            for len in *min..=*max {
                t = t.saturating_add(base.saturating_pow(len as u32));
            }
            t
        }
    };

    if total == 0 {
        eprintln!("No candidates to try");
        std::process::exit(2);
    }

    let resume_u128 = resume_from as u128;
    if resume_u128 >= total {
        eprintln!("Resume offset exceeds total candidates");
        std::process::exit(2);
    }

    let pb_len = if total > u64::MAX as u128 { u64::MAX } else { total as u64 };
    let pb = ProgressBar::new(pb_len);
    pb.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({percent}%) {msg}",
        )
        .unwrap()
        .progress_chars("##-"),
    );

    let monitor = {
        let tested = Arc::clone(&tested);
        let paused = Arc::clone(&paused);
        let stop = Arc::clone(&stop);
        let pb = pb.clone();
        let state = args.state.clone();
        thread::spawn(move || {
            let mut last_rate_instant = Instant::now();
            let mut last_rate_pos = tested.load(Ordering::Relaxed);
            let mut rate_msg = "rate=0/s".to_string();
            while !stop.load(Ordering::Relaxed) {
                let pos = tested.load(Ordering::Relaxed);
                if last_rate_instant.elapsed() >= Duration::from_secs(10) {
                    let delta = pos.saturating_sub(last_rate_pos);
                    let secs = last_rate_instant.elapsed().as_secs_f64().max(1.0);
                    let rate = (delta as f64) / secs;
                    rate_msg = format!("rate={:.2}/s", rate);
                    last_rate_instant = Instant::now();
                    last_rate_pos = pos;
                }
                pb.set_position(pos);
                if paused.load(Ordering::Relaxed) {
                    pb.set_message(format!("paused (press 'p' to resume) {}", rate_msg));
                } else {
                    pb.set_message(format!("running {}", rate_msg));
                }
                write_state(&state, pos);
                thread::sleep(Duration::from_millis(250));
            }
            pb.finish();
        })
    };

    let generator = {
        let tx = tx.clone();
        let found = Arc::clone(&found);
        let paused = Arc::clone(&paused);
        let stop = Arc::clone(&stop);
        thread::spawn(move || match args.mode {
            Mode::Wordlist { path } => {
                let _ = run_wordlist(&path, tx, found, paused, stop, resume_from);
            }
            Mode::Mask { mask } => {
                run_mask(&mask, tx, found, paused, stop, resume_from);
            }
            Mode::Bruteforce { charset, min, max } => {
                run_bruteforce(&charset, min, max, tx, found, paused, stop, resume_from);
            }
        })
    };

    let _ = generator.join();
    drop(tx);
    for h in handles {
        let _ = h.join();
    }

    stop.store(true, Ordering::Relaxed);
    let _ = monitor.join();
    if let Some(h) = input_handle {
        let _ = h.join();
    }

    let found = { result.lock().unwrap().take() };
    if let Some(found) = found {
        println!("FOUND passphrase: {}", found.passphrase);
        if let Some(out) = args.out {
            let _ = fs::write(out, &found.plaintext);
        } else {
            println!("PLAINTEXT: {}", String::from_utf8_lossy(&found.plaintext));
        }
        Ok(())
    } else {
        eprintln!("No match found");
        std::process::exit(1);
    }
}
