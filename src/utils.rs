use super::{HASH_START_INDEX, HASH_STORED_SIZE};
use argon_hash_password::{create_hash_and_salt, hash_and_verify, parse_saltstring};
use std::{error::Error, str};

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
