use clap::{Parser, Subcommand};
use log::{info, warn};
use std::{
    error::Error,
    fs::{metadata, remove_dir_all, remove_file},
};

mod dec;
mod enc;
mod password;
mod stream;
mod utils;

const HASH_START_INDEX: usize = 48;
const HASH_STORED_SIZE: usize = 32;
const SALT_SIZE: usize = 22;
const NONCE_SIZE: usize = 19;
const BUFFER_LEN: usize = 500;

const ENCRYPTED_SUFFIX: &str = ".encrypted";
const DECRYPTED_SUFFIX: &str = ".decrypted";

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
    /// Tar gunzip compress the directory to encrypt
    #[clap(long, short)]
    compress: bool,
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
                None => format!("{}{}", args.source, ENCRYPTED_SUFFIX),
            };
            let md = metadata(&args.source)?;
            if md.is_file() {
                if args.compress {
                    warn!("Compress option is only supported for directory encryption");
                }
                match enc::encrypt_file(&args.source, &dest_path, &password) {
                    Ok(()) => (),
                    Err(e) => {
                        // If failure during encryption then delete the dest file
                        remove_file(&dest_path)?;
                        return Err(e);
                    }
                }
            } else if md.is_dir() {
                match enc::encrypt_dir(&args.source, &dest_path, &password, args.compress) {
                    Ok(()) => (),
                    Err(e) => {
                        remove_dir_all(&dest_path)?;
                        return Err(e);
                    }
                }
            } else {
                return Err(format!("file or directory {:?} does not exist", &args.source).into());
            }
        }
        Action::Dec(args) => {
            let password = match args.password {
                Some(password) => password,
                None => password::get_from_user()?,
            };
            let dest_path = match args.dest {
                Some(dest_path) => dest_path,
                None => {
                    let source = match args.source.strip_suffix(ENCRYPTED_SUFFIX) {
                        Some(source) => source,
                        None => &args.source,
                    };
                    format!("{}{}", source, DECRYPTED_SUFFIX)
                }
            };
            let md = metadata(&args.source)?;
            if md.is_file() {
                match dec::decrypt_file(&args.source, &dest_path, &password) {
                    Ok(()) => (),
                    Err(e) => {
                        // If failure during decryption then delete the dest file
                        remove_file(&dest_path)?;
                        return Err(format!(
                            "incorrect decryption password or malformed encrypted file: {}",
                            e
                        )
                        .into());
                    }
                }
            } else if md.is_dir() {
                unreachable!();
            } else {
                return Err(format!("file or directory {:?} does not exist", &args.source).into());
            }
        }
        Action::Stream(args) => {
            let _password = match args.password {
                Some(password) => password,
                None => password::get_from_user()?,
            };
            info!("not yet implemented");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::{read_to_string, File},
        io::Write,
    };

    const UNENCRYPTED_FILE_NAME: &str = "ecrypt_test.txt";
    const UNENCRYPTED_FILE_TEXT: &str = "Unencrypted text in file";
    const ENCRYPTED_FILE_NAME: &str = "ecrypt_test.txt.encrypted";
    const DECRYPTED_FILE_NAME: &str = "ecrypt_test.txt.decrypted";
    const PASSWORD: &str = "samplePass123";

    fn teardown() {
        remove_file(UNENCRYPTED_FILE_NAME).unwrap();
        remove_file(ENCRYPTED_FILE_NAME).unwrap();
        remove_file(DECRYPTED_FILE_NAME).unwrap();
    }

    #[test]
    fn encrypt_and_decrypt_file() {
        let mut unencrypted_file = File::create(UNENCRYPTED_FILE_NAME).unwrap();
        unencrypted_file
            .write(UNENCRYPTED_FILE_TEXT.as_bytes())
            .unwrap();
        enc::encrypt_file(UNENCRYPTED_FILE_NAME, ENCRYPTED_FILE_NAME, PASSWORD).unwrap();
        dec::decrypt_file(ENCRYPTED_FILE_NAME, DECRYPTED_FILE_NAME, PASSWORD).unwrap();
        assert_eq!(
            read_to_string(DECRYPTED_FILE_NAME).unwrap(),
            UNENCRYPTED_FILE_TEXT
        );
        teardown();
    }
}
