use std::io::{self, BufRead}; // BufRead allows us to read input from the user,
//  which we can use to test our attack against the vulnerable password checker
use std::hint::black_box; //prevents compiler optimizations that could remove 
// the timing differences we're trying to measure

/// The secret password the attacker is trying to recover.
/// In a real scenario this would come from a database or config.
const SECRET: &str = "r4ndomP@ss";

fn vulnerable_check_password (attempt: &str) -> bool {
    
    if attempt.len() != SECRET.len() {
        return false;
    }   

    let attempt_bytes: &[u8] = attempt.as_bytes();
    let secret_bytes: &[u8] = SECRET.as_bytes();

    for i in 0..attempt_bytes.len() {
        // Use black_box to prevent compiler optimizations that could remove the timing differences
        if black_box(attempt_bytes[i]) != black_box(secret_bytes[i]) {
            return false; // This is the Early Exit Vulnerability
        }
        // do_per_char_work makes character takes more time to proccess, substitutes fake thread::sleep 
        // calls with a more realistic per-character cost 
        let _ = black_box(do_per_char_work(secret_bytes[i])); 
    }

    true
}   


//rust compiler will merge work into the caller, this forces the function to remail a real functiion
// which makes the timing more consistent and easier to measure
#[inline(never)]
/// Kept intentionally cheap so the total checker stays fast, but expensive
fn do_per_char_work(byte: u8) -> u64 { // takes actual byte value of input, if always passing u8,
//compiler could precompute the entire loop at compile time and reduce it to a single number
    
    let mut acc: u64 = byte as u64; //Seeds the accumulator with the byte value. u64 is used 
    // because the multiplication below produces very large numbers
    //Starting from the byte value chains the work to the input, preventing the compiler from treating 
    // iterations as independent.

    // A small busy-loop: ~100–200 ns on modern hardware
    for _ in 0..500 {
        acc = black_box(acc.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407));
    }
    acc
}

fn main() {
    // Read one password attempt per line from stdin.
    // The attacker drives this binary as a subprocess and measures wall time
    // from write-to-stdin to read-from-stdout — a pure black-box timing oracle.
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let attempt = line.expect("failed to read line");
        if check_password(&attempt) {
            println!("user authenticated!");
        } else {
            println!("password is incorrect");
        }
    }
}

