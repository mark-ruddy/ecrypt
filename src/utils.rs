use super::{HASH_START_INDEX, HASH_STORED_SIZE};
use argon_hash_password::{create_hash_and_salt, hash_and_verify, parse_saltstring};
use std::{error::Error, fs::File, str};

pub fn fill_hash_from_salt_and_password(
    password: &str,
    salt: &str,
    hash_buffer: &mut [u8],
) -> Result<(), Box<dyn Error>> {
    let saltstring = parse_saltstring(salt)?;
    let hash = hash_and_verify(password, saltstring)?;
    let hash_bytes = hash.as_bytes();
    let hash_bytes_sized = &hash_bytes[HASH_START_INDEX..HASH_START_INDEX + HASH_STORED_SIZE];
    hash_buffer.copy_from_slice(hash_bytes_sized);
    Ok(())
}

pub fn fill_hash_and_salt_from_password(
    password: &str,
    hash_buffer: &mut [u8],
    salt_buffer: &mut [u8],
) -> Result<(), Box<dyn Error>> {
    let (hash, salt) = create_hash_and_salt(password)?;
    let hash_bytes = hash.as_bytes();
    let hash_bytes_sized = &hash_bytes[HASH_START_INDEX..HASH_START_INDEX + HASH_STORED_SIZE];
    salt_buffer.copy_from_slice(salt.as_bytes());
    hash_buffer.copy_from_slice(hash_bytes_sized);
    Ok(())
}

/// The create_new file method is currently in nightly so using this helper function temporarily
/// Deliberately want to return error if the file already exists to avoid unexpected truncation of user files
pub fn create_new(path: &str) -> Result<File, Box<dyn Error>> {
    match File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(file) => Ok(file),
        Err(e) => Err(format!(
            "Failed to create new file '{}', it may exist already: {}",
            path, e
        )
        .into()),
    }
}
