// AUTHORS - Piper
// Version 3: no sleep(), no black_box() — uses volatile reads for per-char timing work.
// Single file: vulnerable checker + attacker in one binary.
// Exports raw timing data to CSV for statistical analysis.
use std::fs::File;
use std::io::Write;
use std::time::Instant;

const SECRET: &str = "r4ndomP@ss";
const CHARSET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
const SAMPLES: usize = 201;

// vulnerable checker

// Per-character busy work using volatile reads to prevent compiler optimization.
// Volatile reads/writes force the compiler to actually perform each memory
// access in order — the loop cannot be collapsed or reordered.
#[inline(never)]
fn do_per_char_work(byte: u8) -> u64 {
    let mut buf: [u64; 4] = [byte as u64, 1, 2, 3];
    for i in 0..50_000_u64 {
        // volatile_read forces the compiler to actually read from memory each iteration.
        // Without this, the optimizer could just skip the whole loop.
        let prev = unsafe { std::ptr::read_volatile(&buf[(i % 4) as usize]) };
        let next = prev
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        unsafe { std::ptr::write_volatile(&mut buf[((i + 1) % 4) as usize], next) };
    }
    // Return the result so the compiler can't prove it's unused and discard it
    unsafe { std::ptr::read_volatile(&buf[0]) }
}

#[inline(never)]
// Vulnerable byte-by-byte password check.
// Early exit on mismatch creates the timing side-channel.
fn vulnerable_check_password(attempt: &str) -> bool {
    if attempt.len() != SECRET.len() {
        return false;
    }

    let attempt_bytes = attempt.as_bytes();
    let secret_bytes = SECRET.as_bytes();

    for i in 0..attempt_bytes.len() {
        if attempt_bytes[i] != secret_bytes[i] {
            return false; // Early exit — the timing side-channel
        }
        // Per-character work makes each matched character take measurably longer
        let _ = do_per_char_work(secret_bytes[i]);
    }

    true
}

// Attacker

// Takes SAMPLES measurements and returns (trimmed_mean, raw_samples).
#[inline(never)]
fn measure_time(attempt: &str) -> (u64, Vec<u64>) {
    let mut times: Vec<u64> = (0..SAMPLES)
        .map(|_| {
            let start = Instant::now();
            let result = vulnerable_check_password(attempt);
            let _ = unsafe { std::ptr::read_volatile(&result) };
            start.elapsed().as_nanos() as u64
        })
        .collect();
    times.sort_unstable();
    // Trim top and bottom 20% and average the middle
    let trim = SAMPLES / 5;
    let trimmed = &times[trim..SAMPLES - trim];
    let trimmed_mean = trimmed.iter().sum::<u64>() / trimmed.len() as u64;
    (trimmed_mean, times)
}

fn attack() {
    let mut known = String::new();
    let mut csv = File::create("timing_data.csv").expect("cannot create CSV");

    // CSV header
    writeln!(csv, "position,character,trimmed_mean_ns,sample_index,raw_time_ns")
        .expect("write failed");

    println!("Starting timing attack...\n");

    for pos in 0..SECRET.len() {
        let mut results: Vec<(char, u64, Vec<u64>)> = CHARSET
            .chars()
            .map(|c| {
                let mut attempt = known.clone();
                attempt.push(c);
                while attempt.len() < SECRET.len() {
                    attempt.push('A');
                }
                let (trimmed_mean, raw_samples) = measure_time(&attempt);
                (c, trimmed_mean, raw_samples)
            })
            .collect();

        // Write every raw sample to CSV
        for (c, trimmed_mean, samples) in &results {
            for (i, &t) in samples.iter().enumerate() {
                writeln!(csv, "{},{},{},{},{}", pos, c, trimmed_mean, i, t)
                    .expect("write failed");
            }
        }

        // Sort descending by trimmed mean
        results.sort_unstable_by(|a, b| b.1.cmp(&a.1));

        let (best_char, best_time, _) = &results[0];
        let gap = best_time - results[1].1;

        known.push(*best_char);
        println!(
            "pos {}: '{}' trimmed_mean={} ns  gap={} ns  -> {}",
            pos, best_char, best_time, gap, known
        );
    }

    println!("\n--- Final Result ---");
    if vulnerable_check_password(&known) {
        println!("SUCCESS! The password is '{}'", known);
    } else {
        println!("FAILED. Best guess was '{}'", known);
    }
    println!("Raw timing data written to timing_data.csv");
}

fn main() {
    attack();
}