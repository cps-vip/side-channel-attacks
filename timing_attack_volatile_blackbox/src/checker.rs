const SECRET: &str = "r4ndomP@ss";

#[inline(never)]
fn do_per_char_work(byte: u8) -> u64 {
    let mut buf: [u64; 4] = [byte as u64, 1, 2, 3];
    for i in 0..50_u64 {
        let prev = unsafe { std::ptr::read_volatile(&buf[(i % 4) as usize]) };
        let next = prev
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        unsafe { std::ptr::write_volatile(&mut buf[((i + 1) % 4) as usize], next) };
    }
    unsafe { std::ptr::read_volatile(&buf[0]) }
}

#[inline(never)]
pub fn check_password(attempt: &str) -> bool {
    if attempt.len() != SECRET.len() {
        return false;
    }
    let attempt_bytes = attempt.as_bytes();
    let secret_bytes = SECRET.as_bytes();
    for i in 0..attempt_bytes.len() {
        if attempt_bytes[i] != secret_bytes[i] {
            return false;
        }
        let _ = do_per_char_work(secret_bytes[i]);
    }
    true
}

pub fn secret_len() -> usize {
    SECRET.len()
}