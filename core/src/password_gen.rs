use rand::{Rng, distributions::Alphanumeric};

pub fn generate_password(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

pub fn generate_multiple_passwords(num: usize, length: usize) -> Vec<String> {
    (0..num).map(|_| generate_password(length)).collect()
}
//