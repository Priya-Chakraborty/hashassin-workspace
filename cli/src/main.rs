mod commands;
use clap::{Parser, Subcommand};
use commands::{gen_passwords, check_passwords, gen_hashes, dump_hashes};

#[derive(Parser)]
#[command(name = "hashassin", version, author, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate passwords and their hashes.
    GenPasswords {
        #[arg(long)]
        num: usize,
        #[arg(long)]
        chars: usize,
        #[arg(long)]
        threads: usize,
        #[arg(long)]
        algorithm: String,
        #[arg(long)]
        out_file: String,
    },
    /// Check passwords against a hash dump.
    CheckPasswords {
        #[arg(long)]
        hash_file: String,
        #[arg(long)]
        password_file: String,
        #[arg(long)]
        algorithm: String,
    },
    /// Generate hashes from an input file of passwords.
    GenHashes {
        #[arg(long)]
        in_file: String,
        #[arg(long)]
        out_file: String,
        #[arg(long)]
        threads: usize,
        #[arg(long)]
        algorithm: String,
    },
    /// Dump (print) hashes from a given hash file.
    DumpHashes {
        #[arg(long)]
        hash_file: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::GenPasswords { num, chars, threads, algorithm, out_file } => {
            gen_passwords(*num, *chars, *threads, algorithm, out_file);
        },
        Commands::CheckPasswords { hash_file, password_file, algorithm } => {
            check_passwords(hash_file, password_file, algorithm);
        },
        Commands::GenHashes { in_file, out_file, threads, algorithm } => {
            gen_hashes(in_file, out_file, *threads, algorithm);
        },
        Commands::DumpHashes { hash_file } => {
            dump_hashes(hash_file);
        },
    }
}
