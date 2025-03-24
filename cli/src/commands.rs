use hashassin_core::{
    hash::{Algorithm, hash_password},
    password_gen,
};
use rayon::prelude::*;
use std::{env, fs, io::Write, path::PathBuf};

pub fn parse_algorithm(alg: &str) -> Algorithm {
    match alg.to_lowercase().as_str() {
        "sha256" => Algorithm::SHA256,
        "sha3-512" => Algorithm::SHA3_512,
        "md5" => Algorithm::MD5,
        "scrypt" => Algorithm::Scrypt,
        _ => panic!("Unknown algorithm"),
    }
}

pub fn gen_passwords(num: usize, chars: usize, threads: usize, algorithm: &str, out_file: &str) {
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
        .unwrap();
    let alg = parse_algorithm(algorithm);

    let passwords = password_gen::generate_multiple_passwords(num, chars);
    let hashes: Vec<String> = passwords
        .par_iter()
        .map(|p| format!("{}:{}", p, hash_password(p, alg)))
        .collect();

    let mut file = fs::File::create(out_file).unwrap();
    for line in hashes {
        writeln!(file, "{line}").unwrap();
    }
    println!("Passwords and hashes written to {}", out_file);
}

pub fn check_passwords(hash_file: &str, password_file: &str, algorithm: &str) {
    let alg = parse_algorithm(algorithm);

    let mut hash_path = PathBuf::from(env::current_dir().unwrap());
    hash_path.push(hash_file);

    let mut password_path = PathBuf::from(env::current_dir().unwrap());
    password_path.push(password_file);

    println!("Debug - Hash path: {:?}", hash_path);
    println!("Debug - Password path: {:?}", password_path);

    let hashes = fs::read_to_string(&hash_path).expect("Hash file not found");
    let passwords = fs::read_to_string(&password_path).expect("Password file not found");

    let hash_set: Vec<&str> = hashes.lines().collect();
    let password_list: Vec<&str> = passwords.lines().collect();

    for pass in password_list {
        let hashed = hash_password(pass, alg);
        if hash_set.contains(&hashed.as_str()) {
            println!("MATCH FOUND: Password '{}' hashes to '{}'", pass, hashed);
        }
    }
}
