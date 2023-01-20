use clap::{Parser, Subcommand};
use log::info;
use std::error::Error;

mod dec;
mod enc;
mod password;
mod stream;

const HASH_STORED_SIZE: usize = 32;
const SALT_SIZE: usize = 22;
const NONCE_SIZE: usize = 19;
const BUFFER_LEN: usize = 500;

#[derive(Subcommand, Debug)]
#[clap(author, version, about, long_about = None)]
enum Action {
    Enc(EncArg),
    Dec(DecArg),
    Stream(StreamArg),
}

#[derive(Parser, Debug)]
struct EncArg {
    /// Password to encrypt with
    #[clap(long, short)]
    password: Option<String>,
    /// Output destination file or directory name
    #[clap(long, short)]
    dest: Option<String>,
    /// Source file or directory to encrypt
    source: String,
}

#[derive(Parser, Debug)]
struct DecArg {
    #[clap(long, short)]
    password: Option<String>,
    /// Output destination file or directory name
    #[clap(long, short)]
    dest: Option<String>,
    // Source file or directory to decrypt
    source: String,
}

#[derive(Parser, Debug)]
struct StreamArg {
    #[clap(long, short)]
    password: Option<String>,
}

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(subcommand)]
    action: Action,
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    match args.action {
        Action::Enc(args) => {
            let password = match args.password {
                Some(password) => password,
                None => password::get_from_user()?,
            };
            let dest_path = match args.dest {
                Some(dest_path) => dest_path,
                None => format!("{}.enc", args.source),
            };
            enc::encrypt_file(&args.source, &dest_path, &password)?;
        }
        Action::Dec(args) => {
            let password = match args.password {
                Some(password) => password,
                None => password::get_from_user()?,
            };
            let dest_path = match args.dest {
                Some(dest_path) => dest_path,
                None => format!("{}.dec", args.source),
            };
            dec::decrypt_file(&args.source, &dest_path, &password)?;
        }
        Action::Stream(args) => {
            let password = match args.password {
                Some(password) => password,
                None => password::get_from_user()?,
            };
            info!("not yet implemented");
        }
    }
    Ok(())
}
