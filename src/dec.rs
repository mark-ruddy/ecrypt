use super::{password::get_argon_hash_of_password, HASH_STORED_SIZE, NONCE_SIZE, SALT_SIZE};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chacha20poly1305::{aead::stream, KeyInit, XChaCha20Poly1305};
use log::info;
use std::{
    error::Error,
    fs::File,
    io::{stdout, Read, Write},
    str,
};
use zeroize::Zeroize;

pub fn decrypt_file(
    source_path: &str,
    dest_path: &str,
    password: &str,
) -> Result<(), Box<dyn Error>> {
    let mut salt = [0u8; SALT_SIZE];
    let mut nonce = [0u8; NONCE_SIZE];

    let mut source_file = File::open(source_path)?;
    let mut dest_file = File::create(dest_path)?;

    let salt_count = source_file.read(&mut salt)?;
    if salt_count != salt.len() {
        return Err(format!("failure reading salt from start of source file").into());
    }

    let nonce_count = source_file.read(&mut nonce)?;
    if nonce_count != nonce.len() {
        return Err(format!("failure reading nonce from start of source file").into());
    }

    stdout().write_all(&salt)?;
    println!(" ");
    stdout().write_all(&nonce)?;

    let mut hash = get_argon_hash_of_password(password, str::from_utf8(&salt)?)?;
    let hash_vec = hash.as_bytes();
    info!(
        "Hash is: {}",
        String::from_utf8_lossy(&hash_vec[HASH_STORED_SIZE..])
    );
    let aead = XChaCha20Poly1305::new(hash_vec[HASH_STORED_SIZE..].as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_LEN: usize = 500;
    let mut buffer = [0u8; BUFFER_LEN];
    loop {
        let read_count = source_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let plaintext = match stream_decryptor.decrypt_next(buffer.as_slice()) {
                Ok(plaintext) => plaintext,
                Err(e) => return Err(format!("failed to decrypt buffer: {}", e).into()),
            };
            dest_file.write(&plaintext)?;
        } else {
            let plaintext = match stream_decryptor.decrypt_next(buffer.as_slice()) {
                Ok(plaintext) => plaintext,
                Err(e) => return Err(format!("failed to decrypt last buffer: {}", e).into()),
            };
            dest_file.write(&plaintext)?;
            break;
        }
    }
    hash.zeroize();
    Ok(())
}
