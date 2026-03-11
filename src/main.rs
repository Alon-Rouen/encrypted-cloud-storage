// ============================================================
// main.rs — CLI entry point
// On déclare les modules directement ici (plus simple, pas de lib.rs nécessaire).
// Les tests dans les sous-modules sont découverts via `cargo test`.
// ============================================================

mod crypto;
mod storage;
mod client;

use client::session::Session;

use std::path::PathBuf;
use anyhow::Result;
use clap::{Parser, Subcommand};

/// Encrypted Cloud Storage — cryptography engineering project.
#[derive(Parser)]
#[command(name = "ecs", version = "0.1.0", about = "Secure encrypted file storage")]
struct Cli {
    #[arg(long, default_value = "vault", global = true)]
    vault: PathBuf,

    #[arg(long, default_value = "user_profile.json", global = true)]
    profile: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Register a new user account.
    Register {
        #[arg(short, long)]
        username: String,
        #[arg(short, long)]
        password: String,
    },
    /// Upload a file to the encrypted vault.
    Upload {
        file: PathBuf,
        #[arg(short, long)]
        password: String,
    },
    /// Download a file from the encrypted vault.
    Download {
        filename: String,
        #[arg(short, long, default_value = ".")]
        dest: PathBuf,
        #[arg(short, long)]
        password: String,
    },
    /// List all files stored in the vault.
    List {
        #[arg(short, long)]
        password: String,
    },
    /// Delete a file from the encrypted vault.
    Delete {
        filename: String,
        #[arg(short, long)]
        password: String,
    },
    /// Run a full end-to-end demo (no arguments needed).
    Demo,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Register { username, password } => {
            Session::register(&username, &password, &cli.vault, &cli.profile)?;
        }
        Commands::Upload { file, password } => {
            let sess = Session::login(&password, &cli.vault, &cli.profile)?;
            sess.upload(&file)?;
        }
        Commands::Download { filename, dest, password } => {
            let sess = Session::login(&password, &cli.vault, &cli.profile)?;
            sess.download(&filename, &dest)?;
        }
        Commands::List { password } => {
            let sess = Session::login(&password, &cli.vault, &cli.profile)?;
            let files = sess.list()?;
            if files.is_empty() {
                println!("(vault is empty)");
            } else {
                println!("{:<40} {:>10}   {}", "filename", "size", "uploaded_at (unix)");
                println!("{}", "-".repeat(70));
                for f in &files { println!("{}", f); }
            }
        }
        Commands::Delete { filename, password } => {
            let sess = Session::login(&password, &cli.vault, &cli.profile)?;
            sess.delete(&filename)?;
        }
        Commands::Demo => {
            run_demo()?;
        }
    }

    Ok(())
}

fn run_demo() -> Result<()> {
    use std::fs;
    use std::path::Path;

    println!("=== Encrypted Cloud Storage - End-to-End Demo ===\n");

    let demo_root    = Path::new("ecs_demo");
    let vault_dir    = demo_root.join("vault");
    let profile_path = demo_root.join("user_profile.json");
    let files_dir    = demo_root.join("files");
    let out_dir      = demo_root.join("downloads");

    if demo_root.exists() { fs::remove_dir_all(demo_root)?; }
    fs::create_dir_all(&files_dir)?;

    println!("[1] Registering user 'alice'...");
    let sess = Session::register("alice", "MyS3cur3P@ss!", &vault_dir, &profile_path)?;

    let f1 = files_dir.join("report.txt");
    let f2 = files_dir.join("keys.csv");
    fs::write(&f1, b"Annual report: revenue increased by 42%.")?;
    fs::write(&f2, b"id,name,secret\n1,Alice,hunter2\n2,Bob,correct-horse")?;

    println!("\n[2] Uploading files...");
    sess.upload(&f1)?;
    sess.upload(&f2)?;

    println!("\n[3] Listing vault (decrypted manifest):");
    for f in sess.list()? { println!("    {}", f); }

    println!("\n[4] Raw vault directory (server view - only UUIDs):");
    for entry in fs::read_dir(&vault_dir)? {
        let path = entry?.path();
        let name = path.file_name().unwrap().to_str().unwrap();
        let size = fs::metadata(&path)?.len();
        println!("    {} ({} bytes, encrypted)", name, size);
    }

    println!("\n[5] Downloading 'report.txt'...");
    sess.download("report.txt", &out_dir)?;
    let recovered = fs::read_to_string(out_dir.join("report.txt"))?;
    println!("    Content: \"{}\"", recovered);

    println!("\n[6] Deleting 'keys.csv'...");
    sess.delete("keys.csv")?;
    println!("    Remaining files: {}", sess.list()?.len());

    println!("\n[7] Login with wrong password (should fail)...");
    match Session::login("wrongpassword", &vault_dir, &profile_path) {
        Err(e) => println!("    Correctly rejected: {}", e),
        Ok(_)  => println!("    ERROR: should have failed!"),
    }

    fs::remove_dir_all(demo_root)?;
    println!("\n=== Demo complete ===");
    Ok(())
}