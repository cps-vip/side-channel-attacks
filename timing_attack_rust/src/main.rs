// AUTHORS - Carter, Estelle
use std::thread;
use std::time::{Duration, Instant};
//use std::io::{self, Write};
//use std::sync::OnceLock;


const SECRET: &str = "Pa55word123";

// -- VULNERABLE PASSWORD CHECKER --
fn vulnerable_check_password (attempt: &str) -> bool {
    
    if attempt.len() != SECRET.len() {
        return false;
    }   

    let attempt_bytes: &[u8] = attempt.as_bytes();
    let secret_bytes: &[u8] = SECRET.as_bytes();

    for i in 0..attempt.len() {
        if attempt_bytes[i] != secret_bytes[i] {
            return false; // This is the Early Exit Vulnerability
        }
        thread::sleep(Duration::from_millis(9)); // Add some time to make the vulnerability more obvious
        // thread::sleep(...) tells OS to stop executing current thread
        // releases CPU to other threads, blocks current thread
    }

    true
}   

// -- ATTACK --
fn attack() {
    let charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    // let found: bool = false;

    //assume  we know the length of the password
    let mut current_attempt = String::new();
    // mut is a mutable variable

    for i in 0..SECRET.len() {
        let mut longest_duration = Duration::new(0, 0);
        let mut probable_char: Option<char> = None;
        
        println!("Position {}...", i);

        for candidate in charset.chars() {
            let mut attempt = current_attempt.clone();
            attempt.push(candidate);
            // .push adds candidate to the end of current_attempt

            // pad with random chars to match len of SECRET
            while attempt.len() < SECRET.len() {
                attempt.push('A'); 
            }
            
            // MEAUSRE EXECUTION TIME

            let start = Instant::now();
            vulnerable_check_password(&attempt);
            let duration = start.elapsed();

            // if this character took long, we passed the check and moved to
            // next character

            if duration > longest_duration {
                longest_duration = duration;
                probable_char = Some(candidate);
            }
        }
        // Unwrap the character from Option<char> to print it
        let best_char = probable_char.unwrap();
        current_attempt.push(best_char);

        println!("  FOUND: '{}' (Time: {:?}) -> Current Guess: {}", best_char, longest_duration, current_attempt);
        
    }

    // print final result
    println!("\nFinal Result:");
    if vulnerable_check_password(&current_attempt) {
        println!("SUCCESS! The password is '{}'", current_attempt);
    } else {
        println!("FAILED. Best guess was '{}'", current_attempt);
    }
}   


//static SECRET: OnceLock<String> = OnceLock::new();

fn main() {
    /*
    println!("Enter password: ");
    let mut input = String::new();

    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    let trimmed_input = input.trim();  // Remove newline character

    SECRET.set(input.trim().to_string()).unwrap(); */

    attack();
}