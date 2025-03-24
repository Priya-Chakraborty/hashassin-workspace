mod commands;
use clap::{Parser, Subcommand};
use commands::{check_passwords, gen_passwords};

#[derive(Parser)]
#[command(name = "hashassin", version, author, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
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
    CheckPasswords {
        #[arg(long)]
        hash_file: String,
        #[arg(long)]
        password_file: String,
        #[arg(long)]
        algorithm: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::GenPasswords {
            num,
            chars,
            threads,
            algorithm,
            out_file,
        } => {
            gen_passwords(*num, *chars, *threads, algorithm, out_file);
        }
        Commands::CheckPasswords {
            hash_file,
            password_file,
            algorithm,
        } => {
            check_passwords(hash_file, password_file, algorithm);
        }
    }
}
