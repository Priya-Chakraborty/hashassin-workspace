use hashassin_core::{password_gen, hash::{hash_password, Algorithm}};
use rayon::prelude::*;
use std::{env, fs, io::Write, path::PathBuf};

/// Parse the algorithm flag into our Algorithm enum.
pub fn parse_algorithm(alg: &str) -> Algorithm {
    match alg.to_lowercase().as_str() {
        "sha256"    => Algorithm::SHA256,
        "sha3-512"  => Algorithm::SHA3_512,
        "md5"       => Algorithm::MD5,
        "scrypt"    => Algorithm::Scrypt,
        _ => panic!("Unknown algorithm"),
    }
}

/// Generates a list of random passwords and outputs each with its hash.
pub fn gen_passwords(num: usize, chars: usize, threads: usize, algorithm: &str, out_file: &str) {
    rayon::ThreadPoolBuilder::new().num_threads(threads).build_global().unwrap();
    let alg = parse_algorithm(algorithm);

    let passwords = password_gen::generate_multiple_passwords(num, chars);
    let hashes: Vec<String> = passwords.par_iter()
        .map(|p| format!("{}:{}", p, hash_password(p, alg)))
        .collect();

    let mut file = fs::File::create(out_file).unwrap();
    for line in hashes {
        writeln!(file, "{line}").unwrap();
    }
    println!("Passwords and hashes written to {}", out_file);
}

/// Checks each password from the given file against the provided hash dump.
pub fn check_passwords(hash_file: &str, password_file: &str, algorithm: &str) {
    let alg = parse_algorithm(algorithm);
    let current_dir = env::current_dir().unwrap();

    let hashes = fs::read_to_string(current_dir.join(hash_file))
        .expect("Hash file not found");
    let passwords = fs::read_to_string(current_dir.join(password_file))
        .expect("Password file not found");

    let hash_set: Vec<&str> = hashes.lines().collect();
    let password_list: Vec<&str> = passwords.lines().collect();

    for pass in password_list {
        let hashed = hash_password(pass, alg);
        if hash_set.contains(&hashed.as_str()) {
            println!("MATCH FOUND: Password '{}' hashes to '{}'", pass, hashed);
        }
    }
}

/// Reads an input file of passwords, computes hashes using the specified algorithm (with multithreading), and writes the results to an output file.
pub fn gen_hashes(in_file: &str, out_file: &str, threads: usize, algorithm: &str) {
    rayon::ThreadPoolBuilder::new().num_threads(threads).build_global().unwrap();
    let alg = parse_algorithm(algorithm);
    let current_dir = env::current_dir().unwrap();

    let passwords = fs::read_to_string(current_dir.join(in_file))
        .expect("Input file not found");
    let password_list: Vec<&str> = passwords.lines().collect();

    let hashes: Vec<String> = password_list.par_iter()
        .map(|p| format!("{}:{}", p, hash_password(p, alg)))
        .collect();

    let mut file = fs::File::create(out_file).unwrap();
    for line in hashes {
        writeln!(file, "{line}").unwrap();
    }
    println!("Hashes written to {}", out_file);
}

/// Dumps the contents of a hash file to standard output.
pub fn dump_hashes(hash_file: &str) {
    let current_dir = env::current_dir().unwrap();
    let hashes = fs::read_to_string(current_dir.join(hash_file))
        .expect("Hash file not found");
    for line in hashes.lines() {
        println!("{}", line);
    }
}
