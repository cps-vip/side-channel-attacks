use std::io::{self, BufRead}; 
use std::hint::black_box;


const SECRET: &str = "r4ndomP@ss";

fn vulnerable_check_password (attempt: &str) -> bool {
    // rejects guesses with wrong length first
    if attempt.len() != SECRET.len() {
        return false;
    }   

    let attempt_bytes: &[u8] = attempt.as_bytes();
    let secret_bytes: &[u8] = SECRET.as_bytes();
    //stop at the first mismatch as it can leak timing information
    for i in 0..attempt_bytes.len() {
       
        if black_box(attempt_bytes[i]) != black_box(secret_bytes[i]) {
            return false; // This is the Early Exit Vulnerability
        }
        
    }

    true
}   


fn main() {
    // Read one password guess per line so the checker can be tested repeatedly
    
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let attempt = line.expect("failed to read line");
        if vulnerable_check_password(&attempt) {
            println!("user authenticated!");
        } else {
            println!("password is incorrect");
        }
    }
}

