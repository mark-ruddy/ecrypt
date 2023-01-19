use clap::{Parser, Subcommand};
use log::info;
use std::error::Error;

mod enc;
mod password;
mod stream;

#[derive(Subcommand, Debug)]
#[clap(author, version, about, long_about = None)]
enum Action {
    Enc(EncArg),
    Stream(StreamArg),
}

#[derive(Parser, Debug)]
struct EncArg {
    /// Password to encrypt with
    #[clap(long, short)]
    password: Option<String>,
    /// File or directory to encrypt
    item: String,
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
            args.item;
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
