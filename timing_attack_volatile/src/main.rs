// // AUTHORS - Piper
// // Version 3: no sleep(), no black_box() — uses volatile reads for per-char timing work.
// // Single file: vulnerable checker + attacker in one binary.
// use std::time::Instant;

// const SECRET: &str = "r4ndomP@ss";
// const CHARSET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
// const SAMPLES: usize = 201;

// // vulnerable checker

// // Per-character busy work using volatile reads to prevent compiler optimization.
// // Volatile reads/writes force the compiler to actually perform each memory
// // access in order — the loop cannot be collapsed or reordered.
// #[inline(never)]
// fn do_per_char_work(byte: u8) -> u64 {
//     let mut buf: [u64; 4] = [byte as u64, 1, 2, 3];
//     for i in 0..50_000_u64 {
//               // volatile_read forces the compiler to actually read from memory each iteration.
//         // Without this, the optimizer could just skip the whole loop.
//         let prev = unsafe { std::ptr::read_volatile(&buf[(i % 4) as usize]) };
//         let next = prev
//             .wrapping_mul(6364136223846793005)
//             .wrapping_add(1442695040888963407);
//         unsafe { std::ptr::write_volatile(&mut buf[((i + 1) % 4) as usize], next) };
//     }
//     // Return the result so the compiler can't prove it's unused and discard it
//     unsafe { std::ptr::read_volatile(&buf[0]) }
// }

// #[inline(never)]
// // Vulnerable byte-by-byte password check.
// // Early exit on mismatch creates the timing side-channel.
// fn vulnerable_check_password(attempt: &str) -> bool {
//     if attempt.len() != SECRET.len() {
//         return false;
//     }

//     let attempt_bytes = attempt.as_bytes();
//     let secret_bytes = SECRET.as_bytes();

//     for i in 0..attempt_bytes.len() {
//         if attempt_bytes[i] != secret_bytes[i] {
//             return false; // Early exit — the timing side-channel
//         }
//         // Per-character work makes each matched character take measurably longer
//         let _ = do_per_char_work(secret_bytes[i]);
//     }

//     true
// }

// // Attacker

// /// Takes SAMPLES measurements and returns the median for stability.
// #[inline(never)]
// fn median_time(attempt: &str) -> u64 {
//     let mut times: Vec<u64> = (0..SAMPLES)
//         .map(|_| {
//             let start = Instant::now();
//             let result = vulnerable_check_password(attempt);
//             let _ = unsafe { std::ptr::read_volatile(&result) };
//             start.elapsed().as_nanos() as u64
//         })
//         .collect();
//     times.sort_unstable();
//     // Trim top and bottom 20% and average the middle
//     let trim = SAMPLES / 5;
//     let trimmed = &times[trim..SAMPLES - trim];
//     trimmed.iter().sum::<u64>() / trimmed.len() as u64
// }

// fn attack() {
//     let mut known = String::new();

//     println!("Starting timing attack...\n");

//     for pos in 0..SECRET.len() {
//         let mut times: Vec<(char, u64)> = CHARSET
//             .chars()
//             .map(|c| {
//                 let mut attempt = known.clone();
//                 attempt.push(c);
//                 while attempt.len() < SECRET.len() {
//                     attempt.push('A');
//                 }
//                 (c, median_time(&attempt))
//             })
//             .collect();

//         // Sort descending by time
//         times.sort_unstable_by(|a, b| b.1.cmp(&a.1));

//         let (best_char, best_time) = times[0];
//         let gap = best_time - times[1].1; // gap between 1st and 2nd best

//         known.push(best_char);
//         println!(
//             "pos {}: '{}' median={} ns  gap={} ns  -> {}",
//             pos, best_char, best_time, gap, known
//         );
//     }

//     println!("\n--- Final Result ---");
//     if vulnerable_check_password(&known) {
//         println!("SUCCESS! The password is '{}'", known);
//     } else {
//         println!("FAILED. Best guess was '{}'", known);
//     }
// }

// fn main() {
//     attack();
// }















// use std::fs::OpenOptions;
// use std::io::{Result, Write};
// use std::time::Instant;

// const SECRET: &str = "r4ndomP@ss";
// const CHARSET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
// const SAMPLES: usize = 201;
// const RUNS: usize = 20; // how many full attacks to perform

// #[inline(never)]
// fn do_per_char_work(byte: u8) -> u64 {
//     let mut buf: [u64; 4] = [byte as u64, 1, 2, 3];
//     for i in 0..50_000_u64 {
//         let prev = unsafe { std::ptr::read_volatile(&buf[(i % 4) as usize]) };
//         let next = prev
//             .wrapping_mul(6364136223846793005)
//             .wrapping_add(1442695040888963407);
//         unsafe { std::ptr::write_volatile(&mut buf[((i + 1) % 4) as usize], next) };
//     }
//     unsafe { std::ptr::read_volatile(&buf[0]) }
// }

// #[inline(never)]
// fn vulnerable_check_password(attempt: &str) -> bool {
//     if attempt.len() != SECRET.len() {
//         return false;
//     }

//     let attempt_bytes = attempt.as_bytes();
//     let secret_bytes = SECRET.as_bytes();

//     for i in 0..attempt_bytes.len() {
//         if attempt_bytes[i] != secret_bytes[i] {
//             return false;
//         }
//         let _ = do_per_char_work(secret_bytes[i]);
//     }

//     true
// }

// // NOTE: this is actually a trimmed mean, not a median.
// #[inline(never)]
// fn median_time(attempt: &str) -> u64 {
//     let mut times: Vec<u64> = (0..SAMPLES)
//         .map(|_| {
//             let start = Instant::now();
//             let result = vulnerable_check_password(attempt);
//             let _ = unsafe { std::ptr::read_volatile(&result) };
//             start.elapsed().as_nanos() as u64
//         })
//         .collect();

//     times.sort_unstable();

//     let trim = SAMPLES / 5;
//     let trimmed = &times[trim..SAMPLES - trim];
//     trimmed.iter().sum::<u64>() / trimmed.len() as u64
// }

// struct AttackStats {
//     guessed_password: String,
//     success: bool,
//     runtime_ns: u128,
//     avg_gap_ns: f64,
// }

// fn attack() -> AttackStats {
//     let attack_start = Instant::now();
//     let mut known = String::new();
//     let mut gap_sum: u128 = 0;
//     let mut gap_count: usize = 0;

//     println!("Starting timing attack...\n");

//     for pos in 0..SECRET.len() {
//         let mut times: Vec<(char, u64)> = CHARSET
//             .chars()
//             .map(|c| {
//                 let mut attempt = known.clone();
//                 attempt.push(c);
//                 while attempt.len() < SECRET.len() {
//                     attempt.push('A');
//                 }
//                 (c, median_time(&attempt))
//             })
//             .collect();

//         times.sort_unstable_by(|a, b| b.1.cmp(&a.1));

//         let (best_char, best_time) = times[0];
//         let second_best_time = times[1].1;
//         let gap = best_time - second_best_time;

//         gap_sum += gap as u128;
//         gap_count += 1;

//         known.push(best_char);

//         println!(
//             "pos {}: '{}' score={} ns  gap={} ns  -> {}",
//             pos, best_char, best_time, gap, known
//         );
//     }

//     let success = vulnerable_check_password(&known);
//     let runtime_ns = attack_start.elapsed().as_nanos();
//     let avg_gap_ns = if gap_count > 0 {
//         gap_sum as f64 / gap_count as f64
//     } else {
//         0.0
//     };

//     println!("\n--- Final Result ---");
//     if success {
//         println!("SUCCESS! The password is '{}'", known);
//     } else {
//         println!("FAILED. Best guess was '{}'", known);
//     }

//     AttackStats {
//         guessed_password: known,
//         success,
//         runtime_ns,
//         avg_gap_ns,
//     }
// }

// fn write_csv_header_if_needed(path: &str) -> Result<()> {
//     let file_exists = std::path::Path::new(path).exists();

//     if !file_exists {
//         let mut file = OpenOptions::new()
//             .create(true)
//             .append(true)
//             .open(path)?;
//         writeln!(
//             file,
//             "samples,run,guessed_password,success,runtime_ns,avg_gap_ns"
//         )?;
//     }

//     Ok(())
// }

// fn append_run_to_csv(path: &str, run_num: usize, stats: &AttackStats) -> Result<()> {
//     let mut file = OpenOptions::new()
//         .create(true)
//         .append(true)
//         .open(path)?;

//     writeln!(
//         file,
//         "{},{},{},{},{},{}",
//         SAMPLES,
//         run_num,
//         stats.guessed_password,
//         stats.success,
//         stats.runtime_ns,
//         stats.avg_gap_ns
//     )?;

//     Ok(())
// }

// fn main() -> Result<()> {
//     let csv_path = "attack_stats.csv";

//     write_csv_header_if_needed(csv_path)?;

//     for run in 1..=RUNS {
//         println!("\n==============================");
//         println!("RUN {} / {}", run, RUNS);
//         println!("==============================");

//         let stats = attack();

//         append_run_to_csv(csv_path, run, &stats)?;

//         println!(
//             "Saved: samples={}, run={}, success={}, runtime_ns={}, avg_gap_ns={:.2}",
//             SAMPLES, run, stats.success, stats.runtime_ns, stats.avg_gap_ns
//         );
//     }

//     println!("\nDone. Results saved to {}", csv_path);
//     Ok(())
// }











































// use std::fs::OpenOptions;
// use std::io::{Result, Write};
// use std::time::Instant;

// const SECRET: &str = "r4ndomP@ss";
// const CHARSET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
// const SAMPLES: usize = 1;
// const RUNS: usize = 20; // how many full attacks to perform

// #[inline(never)]
// fn do_per_char_work(byte: u8) -> u64 {
//     let mut buf: [u64; 4] = [byte as u64, 1, 2, 3];
//     for i in 0..50_000_u64 {
//         let prev = unsafe { std::ptr::read_volatile(&buf[(i % 4) as usize]) };
//         let next = prev
//             .wrapping_mul(6364136223846793005)
//             .wrapping_add(1442695040888963407);
//         unsafe { std::ptr::write_volatile(&mut buf[((i + 1) % 4) as usize], next) };
//     }
//     unsafe { std::ptr::read_volatile(&buf[0]) }
// }

// #[inline(never)]
// fn vulnerable_check_password(attempt: &str) -> bool {
//     if attempt.len() != SECRET.len() {
//         return false;
//     }

//     let attempt_bytes = attempt.as_bytes();
//     let secret_bytes = SECRET.as_bytes();

//     for i in 0..attempt_bytes.len() {
//         if attempt_bytes[i] != secret_bytes[i] {
//             return false;
//         }
//         let _ = do_per_char_work(secret_bytes[i]);
//     }

//     true
// }

// // NOTE: this is actually a trimmed mean, not a median.
// #[inline(never)]
// fn trimmed_mean_time(attempt: &str) -> u64 {
//     let mut times: Vec<u64> = (0..SAMPLES)
//         .map(|_| {
//             let start = Instant::now();
//             let result = vulnerable_check_password(attempt);
//             let _ = unsafe { std::ptr::read_volatile(&result) };
//             start.elapsed().as_nanos() as u64
//         })
//         .collect();

//     times.sort_unstable();

//     let trim = SAMPLES / 5;
//     let trimmed = &times[trim..SAMPLES - trim];
//     trimmed.iter().sum::<u64>() / trimmed.len() as u64
// }

// #[derive(Debug)]
// struct PositionStat {
//     position: usize,
//     chosen_char: char,
//     correct_char: char,
//     chosen_score_ns: u64,
//     second_char: char,
//     second_score_ns: u64,
//     gap_ns: u64,
//     was_correct: bool,
//     partial_guess: String,
// }

// #[derive(Debug)]
// struct AttackStats {
//     guessed_password: String,
//     success: bool,
//     runtime_ns: u128,
//     avg_gap_ns: f64,
//     position_stats: Vec<PositionStat>,
// }

// fn attack() -> AttackStats {
//     let attack_start = Instant::now();
//     let mut known = String::new();
//     let mut gap_sum: u128 = 0;
//     let mut gap_count: usize = 0;
//     let mut position_stats: Vec<PositionStat> = Vec::new();

//     println!("Starting timing attack...\n");

//     for pos in 0..SECRET.len() {
//         let mut times: Vec<(char, u64)> = CHARSET
//             .chars()
//             .map(|c| {
//                 let mut attempt = known.clone();
//                 attempt.push(c);
//                 while attempt.len() < SECRET.len() {
//                     attempt.push('A');
//                 }
//                 (c, trimmed_mean_time(&attempt))
//             })
//             .collect();

//         times.sort_unstable_by(|a, b| b.1.cmp(&a.1));

//         let (best_char, best_time) = times[0];
//         let (second_char, second_time) = times[1];
//         let gap = best_time - second_time;

//         gap_sum += gap as u128;
//         gap_count += 1;

//         known.push(best_char);

//         let correct_char = SECRET.as_bytes()[pos] as char;
//         let was_correct = best_char == correct_char;

//         position_stats.push(PositionStat {
//             position: pos,
//             chosen_char: best_char,
//             correct_char,
//             chosen_score_ns: best_time,
//             second_char,
//             second_score_ns: second_time,
//             gap_ns: gap,
//             was_correct,
//             partial_guess: known.clone(),
//         });

//         println!(
//             "pos {}: best='{}' score={} ns | second='{}' score={} ns | gap={} ns | correct={} -> {}",
//             pos,
//             best_char,
//             best_time,
//             second_char,
//             second_time,
//             gap,
//             was_correct,
//             known
//         );
//     }

//     let success = vulnerable_check_password(&known);
//     let runtime_ns = attack_start.elapsed().as_nanos();
//     let avg_gap_ns = if gap_count > 0 {
//         gap_sum as f64 / gap_count as f64
//     } else {
//         0.0
//     };

//     println!("\n--- Final Result ---");
//     if success {
//         println!("SUCCESS! The password is '{}'", known);
//     } else {
//         println!("FAILED. Best guess was '{}'", known);
//     }

//     AttackStats {
//         guessed_password: known,
//         success,
//         runtime_ns,
//         avg_gap_ns,
//         position_stats,
//     }
// }

// fn write_attack_csv_header_if_needed(path: &str) -> Result<()> {
//     let file_exists = std::path::Path::new(path).exists();

//     if !file_exists {
//         let mut file = OpenOptions::new()
//             .create(true)
//             .append(true)
//             .open(path)?;
//         writeln!(
//             file,
//             "samples,run,guessed_password,success,runtime_ns,avg_gap_ns"
//         )?;
//     }

//     Ok(())
// }

// fn write_position_csv_header_if_needed(path: &str) -> Result<()> {
//     let file_exists = std::path::Path::new(path).exists();

//     if !file_exists {
//         let mut file = OpenOptions::new()
//             .create(true)
//             .append(true)
//             .open(path)?;
//         writeln!(
//             file,
//             "samples,run,position,chosen_char,correct_char,chosen_score_ns,second_char,second_score_ns,gap_ns,was_correct,partial_guess"
//         )?;
//     }

//     Ok(())
// }

// fn append_run_to_csv(path: &str, run_num: usize, stats: &AttackStats) -> Result<()> {
//     let mut file = OpenOptions::new()
//         .create(true)
//         .append(true)
//         .open(path)?;

//     writeln!(
//         file,
//         "{},{},{},{},{},{}",
//         SAMPLES,
//         run_num,
//         stats.guessed_password,
//         stats.success,
//         stats.runtime_ns,
//         stats.avg_gap_ns
//     )?;

//     Ok(())
// }

// fn append_position_stats_to_csv(path: &str, run_num: usize, stats: &AttackStats) -> Result<()> {
//     let mut file = OpenOptions::new()
//         .create(true)
//         .append(true)
//         .open(path)?;

//     for ps in &stats.position_stats {
//         writeln!(
//             file,
//             "{},{},{},{},{},{},{},{},{},{},{}",
//             SAMPLES,
//             run_num,
//             ps.position,
//             ps.chosen_char,
//             ps.correct_char,
//             ps.chosen_score_ns,
//             ps.second_char,
//             ps.second_score_ns,
//             ps.gap_ns,
//             ps.was_correct,
//             ps.partial_guess
//         )?;
//     }

//     Ok(())
// }

// fn main() -> Result<()> {
//     let attack_csv_path = "attack_stats.csv";
//     let position_csv_path = "attack_position_stats.csv";

//     write_attack_csv_header_if_needed(attack_csv_path)?;
//     write_position_csv_header_if_needed(position_csv_path)?;

//     for run in 1..=RUNS {
//         println!("\n==============================");
//         println!("RUN {} / {}", run, RUNS);
//         println!("==============================");

//         let stats = attack();

//         append_run_to_csv(attack_csv_path, run, &stats)?;
//         append_position_stats_to_csv(position_csv_path, run, &stats)?;

//         println!(
//             "Saved run summary to {} and per-position stats to {}",
//             attack_csv_path, position_csv_path
//         );
//         println!(
//             "Summary: samples={}, run={}, success={}, runtime_ns={}, avg_gap_ns={:.2}",
//             SAMPLES, run, stats.success, stats.runtime_ns, stats.avg_gap_ns
//         );
//     }

//     println!("\nDone.");
//     println!("Run-level results saved to {}", attack_csv_path);
//     println!("Per-position results saved to {}", position_csv_path);

//     Ok(())
// }

























// use std::fs::OpenOptions;
// use std::io::{Result, Write};
// use std::time::Instant;

// const SECRET: &str = "r4ndomP@ss";
// const CHARSET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
// const SAMPLES: usize = 101;
// const RUNS: usize = 10000;

// #[inline(never)]
// fn do_per_char_work(byte: u8) -> u64 {
//     let mut buf: [u64; 4] = [byte as u64, 1, 2, 3];
//     for i in 0..50_u64 {
//         let prev = unsafe { std::ptr::read_volatile(&buf[(i % 4) as usize]) };
//         let next = prev
//             .wrapping_mul(6364136223846793005)
//             .wrapping_add(1442695040888963407);
//         unsafe { std::ptr::write_volatile(&mut buf[((i + 1) % 4) as usize], next) };
//     }
//     unsafe { std::ptr::read_volatile(&buf[0]) }
// }

// #[inline(never)]
// fn vulnerable_check_password(attempt: &str) -> bool {
//     if attempt.len() != SECRET.len() {
//         return false;
//     }

//     let attempt_bytes = attempt.as_bytes();
//     let secret_bytes = SECRET.as_bytes();

//     for i in 0..attempt_bytes.len() {
//         if attempt_bytes[i] != secret_bytes[i] {
//             return false;
//         }
//         let _ = do_per_char_work(secret_bytes[i]);
//     }

//     true
// }

// #[inline(never)]
// fn trimmed_mean_time(attempt: &str) -> u64 {
//     let mut times: Vec<u64> = (0..SAMPLES)
//         .map(|_| {
//             let start = Instant::now();
//             let result = vulnerable_check_password(attempt);
//             let _ = unsafe { std::ptr::read_volatile(&result) };
//             start.elapsed().as_nanos() as u64
//         })
//         .collect();

//     times.sort_unstable();

//     let trim = SAMPLES / 5;
//     let trimmed = &times[trim..SAMPLES - trim];
//     trimmed.iter().sum::<u64>() / trimmed.len() as u64
// }

// #[derive(Debug)]
// struct PositionStat {
//     position: usize,
//     chosen_char: char,
//     correct_char: char,
//     chosen_score_ns: u64,
//     second_char: char,
//     second_score_ns: u64,
//     gap_ns: u64,
//     gap_ratio: f64,      // NEW
//     was_correct: bool,
//     partial_guess: String,
// }

// #[derive(Debug)]
// struct AttackStats {
//     guessed_password: String,
//     success: bool,
//     runtime_ns: u128,
//     avg_gap_ns: f64,
//     avg_gap_ratio: f64,  // NEW
//     position_stats: Vec<PositionStat>,
// }

// fn attack() -> AttackStats {
//     let attack_start = Instant::now();
//     let mut known = String::new();
//     let mut gap_sum: u128 = 0;
//     let mut gap_ratio_sum: f64 = 0.0;  // NEW
//     let mut gap_count: usize = 0;
//     let mut position_stats: Vec<PositionStat> = Vec::new();

//     println!("Starting timing attack...\n");

//     for pos in 0..SECRET.len() {
//         let mut times: Vec<(char, u64)> = CHARSET
//             .chars()
//             .map(|c| {
//                 let mut attempt = known.clone();
//                 attempt.push(c);
//                 while attempt.len() < SECRET.len() {
//                     attempt.push('A');
//                 }
//                 (c, trimmed_mean_time(&attempt))
//             })
//             .collect();

//         times.sort_unstable_by(|a, b| b.1.cmp(&a.1));

//         let (best_char, best_time) = times[0];
//         let (second_char, second_time) = times[1];
//         let gap = best_time - second_time;
//         let gap_ratio = best_time as f64 / second_time as f64;  // NEW

//         gap_sum += gap as u128;
//         gap_ratio_sum += gap_ratio;  // NEW
//         gap_count += 1;

//         known.push(best_char);

//         let correct_char = SECRET.as_bytes()[pos] as char;
//         let was_correct = best_char == correct_char;

//         position_stats.push(PositionStat {
//             position: pos,
//             chosen_char: best_char,
//             correct_char,
//             chosen_score_ns: best_time,
//             second_char,
//             second_score_ns: second_time,
//             gap_ns: gap,
//             gap_ratio,  // NEW
//             was_correct,
//             partial_guess: known.clone(),
//         });

//         println!(
//             "pos {}: best='{}' score={} ns | second='{}' score={} ns | gap={} ns | ratio={:.4} | correct={} -> {}",
//             pos, best_char, best_time, second_char, second_time, gap, gap_ratio, was_correct, known
//         );
//     }

//     let success = vulnerable_check_password(&known);
//     let runtime_ns = attack_start.elapsed().as_nanos();
//     let avg_gap_ns = if gap_count > 0 { gap_sum as f64 / gap_count as f64 } else { 0.0 };
//     let avg_gap_ratio = if gap_count > 0 { gap_ratio_sum / gap_count as f64 } else { 0.0 };  // NEW

//     println!("\n--- Final Result ---");
//     if success {
//         println!("SUCCESS! The password is '{}'", known);
//     } else {
//         println!("FAILED. Best guess was '{}'", known);
//     }

//     AttackStats {
//         guessed_password: known,
//         success,
//         runtime_ns,
//         avg_gap_ns,
//         avg_gap_ratio,  // NEW
//         position_stats,
//     }
// }

// fn write_attack_csv_header_if_needed(path: &str) -> Result<()> {
//     if !std::path::Path::new(path).exists() {
//         let mut file = OpenOptions::new().create(true).append(true).open(path)?;
//         writeln!(file, "samples,run,guessed_password,success,runtime_ns,avg_gap_ns,avg_gap_ratio")?;  // NEW col
//     }
//     Ok(())
// }

// fn write_position_csv_header_if_needed(path: &str) -> Result<()> {
//     if !std::path::Path::new(path).exists() {
//         let mut file = OpenOptions::new().create(true).append(true).open(path)?;
//         writeln!(file, "samples,run,position,chosen_char,correct_char,chosen_score_ns,second_char,second_score_ns,gap_ns,gap_ratio,was_correct,partial_guess")?;  // NEW col
//     }
//     Ok(())
// }

// fn append_run_to_csv(path: &str, run_num: usize, stats: &AttackStats) -> Result<()> {
//     let mut file = OpenOptions::new().create(true).append(true).open(path)?;
//     writeln!(
//         file,
//         "{},{},{},{},{},{},{}",
//         SAMPLES, run_num, stats.guessed_password, stats.success,
//         stats.runtime_ns, stats.avg_gap_ns, stats.avg_gap_ratio  // NEW
//     )?;
//     Ok(())
// }

// fn append_position_stats_to_csv(path: &str, run_num: usize, stats: &AttackStats) -> Result<()> {
//     let mut file = OpenOptions::new().create(true).append(true).open(path)?;
//     for ps in &stats.position_stats {
//         writeln!(
//             file,
//             "{},{},{},{},{},{},{},{},{},{},{},{}",
//             SAMPLES, run_num, ps.position, ps.chosen_char, ps.correct_char,
//             ps.chosen_score_ns, ps.second_char, ps.second_score_ns,
//             ps.gap_ns, ps.gap_ratio, ps.was_correct, ps.partial_guess  // NEW
//         )?;
//     }
//     Ok(())
// }

// fn main() -> Result<()> {
//     let attack_csv_path = "attack_stats.csv";
//     let position_csv_path = "attack_position_stats.csv";

//     write_attack_csv_header_if_needed(attack_csv_path)?;
//     write_position_csv_header_if_needed(position_csv_path)?;

//     for run in 1..=RUNS {
//         println!("\n==============================");
//         println!("RUN {} / {}", run, RUNS);
//         println!("==============================");

//         let stats = attack();

//         append_run_to_csv(attack_csv_path, run, &stats)?;
//         append_position_stats_to_csv(position_csv_path, run, &stats)?;

//         println!(
//             "Summary: samples={}, run={}, success={}, runtime_ns={}, avg_gap_ns={:.2}, avg_gap_ratio={:.4}",
//             SAMPLES, run, stats.success, stats.runtime_ns, stats.avg_gap_ns, stats.avg_gap_ratio
//         );
//     }

//     println!("\nDone. Results in {} and {}", attack_csv_path, position_csv_path);
//     Ok(())
// }















use std::fs::OpenOptions;
use std::io::{Result, Write};
use std::time::Instant;

const SECRET: &str = "r4ndomP@ss";
const CHARSET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
const SAMPLES: usize = 101;
const RUNS: usize = 20;

const ITER_SWEEP: &[u64] = &[50000, 10000, 1000, 500, 50, 20, 1];

#[inline(never)]
fn do_per_char_work(byte: u8, iters: u64) -> u64 {
    let mut buf: [u64; 4] = [byte as u64, 1, 2, 3];
    for i in 0..iters {
        let prev = unsafe { std::ptr::read_volatile(&buf[(i % 4) as usize]) };
        let next = prev
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        unsafe { std::ptr::write_volatile(&mut buf[((i + 1) % 4) as usize], next) };
    }
    unsafe { std::ptr::read_volatile(&buf[0]) }
}

#[inline(never)]
fn vulnerable_check_password(attempt: &str, iters: u64) -> bool {
    if attempt.len() != SECRET.len() {
        return false;
    }
    let attempt_bytes = attempt.as_bytes();
    let secret_bytes = SECRET.as_bytes();
    for i in 0..attempt_bytes.len() {
        if attempt_bytes[i] != secret_bytes[i] {
            return false;
        }
        let _ = do_per_char_work(secret_bytes[i], iters);
    }
    true
}

#[inline(never)]
fn trimmed_mean_time(attempt: &str, iters: u64) -> u64 {
    let mut times: Vec<u64> = (0..SAMPLES)
        .map(|_| {
            let start = Instant::now();
            let result = vulnerable_check_password(attempt, iters);
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
    correct_char: char,
    chosen_score_ns: u64,
    second_char: char,
    second_score_ns: u64,
    gap_ns: u64,
    gap_ratio: f64,
    was_correct: bool,
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

fn attack(iters: u64) -> AttackStats {
    let attack_start = Instant::now();
    let mut known = String::new();
    let mut gap_sum: u128 = 0;
    let mut gap_ratio_sum: f64 = 0.0;
    let mut gap_count: usize = 0;
    let mut position_stats: Vec<PositionStat> = Vec::new();

    for pos in 0..SECRET.len() {
        let mut times: Vec<(char, u64)> = CHARSET
            .chars()
            .map(|c| {
                let mut attempt = known.clone();
                attempt.push(c);
                while attempt.len() < SECRET.len() {
                    attempt.push('A');
                }
                (c, trimmed_mean_time(&attempt, iters))
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

        let correct_char = SECRET.as_bytes()[pos] as char;
        let was_correct = best_char == correct_char;

        position_stats.push(PositionStat {
            position: pos,
            chosen_char: best_char,
            correct_char,
            chosen_score_ns: best_time,
            second_char,
            second_score_ns: second_time,
            gap_ns: gap,
            gap_ratio,
            was_correct,
            partial_guess: known.clone(),
        });

        println!(
            "pos {}: best='{}' score={} ns | second='{}' score={} ns | gap={} ns | ratio={:.4} | correct={} -> {}",
            pos, best_char, best_time, second_char, second_time, gap, gap_ratio, was_correct, known
        );
    }

    let success = vulnerable_check_password(&known, iters);
    let runtime_ns = attack_start.elapsed().as_nanos();
    let avg_gap_ns = if gap_count > 0 { gap_sum as f64 / gap_count as f64 } else { 0.0 };
    let avg_gap_ratio = if gap_count > 0 { gap_ratio_sum / gap_count as f64 } else { 0.0 };

    println!("\n--- Final Result ---");
    if success { println!("SUCCESS! The password is '{}'", known); }
    else { println!("FAILED. Best guess was '{}'", known); }

    AttackStats { guessed_password: known, success, runtime_ns, avg_gap_ns, avg_gap_ratio, position_stats }
}

fn write_attack_csv_header_if_needed(path: &str) -> Result<()> {
    if !std::path::Path::new(path).exists() {
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(file, "iters,samples,run,guessed_password,success,runtime_ns,avg_gap_ns,avg_gap_ratio")?;
    }
    Ok(())
}

fn write_position_csv_header_if_needed(path: &str) -> Result<()> {
    if !std::path::Path::new(path).exists() {
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(file, "iters,samples,run,position,chosen_char,correct_char,chosen_score_ns,second_char,second_score_ns,gap_ns,gap_ratio,was_correct,partial_guess")?;
    }
    Ok(())
}

fn append_run_to_csv(path: &str, iters: u64, run_num: usize, stats: &AttackStats) -> Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{},{},{},{},{},{},{},{}", iters, SAMPLES, run_num, stats.guessed_password, stats.success, stats.runtime_ns, stats.avg_gap_ns, stats.avg_gap_ratio)?;
    Ok(())
}

fn append_position_stats_to_csv(path: &str, iters: u64, run_num: usize, stats: &AttackStats) -> Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    for ps in &stats.position_stats {
        writeln!(file, "{},{},{},{},{},{},{},{},{},{},{},{},{}", iters, SAMPLES, run_num, ps.position, ps.chosen_char, ps.correct_char, ps.chosen_score_ns, ps.second_char, ps.second_score_ns, ps.gap_ns, ps.gap_ratio, ps.was_correct, ps.partial_guess)?;
    }
    Ok(())
}
fn main() -> Result<()> {
    let attack_csv_path = "iter_sweep_stats.csv";
    let position_csv_path = "iter_sweep_position_stats.csv";

    write_attack_csv_header_if_needed(attack_csv_path)?;
    write_position_csv_header_if_needed(position_csv_path)?;

    for &iters in ITER_SWEEP {
        println!("iters={}", iters);
        for run in 1..=RUNS {
            println!("run {} / {} (iters={})", run, RUNS, iters);
            let stats = attack(iters);
            append_run_to_csv(attack_csv_path, iters, run, &stats)?;
            append_position_stats_to_csv(position_csv_path, iters, run, &stats)?;
            println!("done: iters={}, run={}, success={}, avg_gap_ns={:.2}", iters, run, stats.success, stats.avg_gap_ns);
        }
    }

    println!("done. results in {} and {}", attack_csv_path, position_csv_path);
    Ok(())
}