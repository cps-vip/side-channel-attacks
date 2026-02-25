// author - Piper
// use std::env;
// use std::process;
use std::thread;
use std::time::Duration;
use std::io::{self, BufRead};

const SECRET: &str = "Pa55word123";


/// Checks a password attempt against SECRET using byte-by-byte comparison.
/// Vulnerable to timing attacks due to early exit and per-character delay.
fn vulnerable_check_password (attempt: &str) -> bool {
    if attempt.len() != SECRET.len() {
        return false;
    }   

    let attempt_bytes = attempt.as_bytes();
    let secret_bytes = SECRET.as_bytes();

    for i in 0..attempt.len() {
        if attempt_bytes[i] != secret_bytes[i] {
            return false; //early exit leak
        }
        // Artificial delay to exaggerate the timing side-channel
        thread::sleep(Duration::from_millis(9));
    }

    true
}   

fn main() {
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let guess = match line {
            Ok(s) => s.trim_end().to_string(),
            Err(_) => break,
        };
        let ok = vulnerable_check_password(&guess);
        if ok {
            println!("OK");
        } else {
            println!("NO");
        }
    }

    // let args: Vec<String> = env::args().collect();
    // if args.len() != 2 {
    //     eprintln!("ussage: target <guess>");
    //     process::exit(2)
    // }
    // let guess = &args[1];
    // if vulnerable_check_password(guess) {
    //     process::exit(0);
    // } else {
    //     process::exit(1);
    // }
}

