use crate::SALT_SIZE;

use super::{password::get_argon_hash_of_password, BUFFER_LEN, HASH_STORED_SIZE, NONCE_SIZE};
use argon_hash_password::create_hash_and_salt;
use chacha20poly1305::{aead::stream, KeyInit, XChaCha20Poly1305};
use log::info;
use rand::{rngs::OsRng, RngCore};
use std::{
    error::Error,
    fs::File,
    io::{stdout, Read, Write},
    str,
};
use zeroize::Zeroize;

pub fn encrypt_file(
    source_path: &str,
    dest_path: &str,
    password: &str,
) -> Result<(), Box<dyn Error>> {
    // Nonce total size will be 32, 19 bytes generated to start: https://docs.rs/aead/latest/aead/stream/struct.StreamBE32.html
    let mut nonce = [0u8; NONCE_SIZE];
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut nonce);
    OsRng.fill_bytes(&mut salt);

    assert_eq!(salt.len(), SALT_SIZE);
    let mut hash = get_argon_hash_of_password(password, str::from_utf8(&salt)?)?;
    let hash_vec = hash.as_bytes();
    info!(
        "Hash is: {}",
        String::from_utf8_lossy(&hash_vec[HASH_STORED_SIZE..])
    );
    let aead = XChaCha20Poly1305::new(hash_vec[HASH_STORED_SIZE..].as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    let mut source_file = File::open(source_path)?;
    let mut dest_file = File::create(dest_path)?;

    // Write the salt and the nonce to the start of the dest file
    // info!("nonce is: {:?}", nonce);

    info!("salt is: {}\n", str::from_utf8(&salt)?);
    stdout().write_all(&nonce)?;

    dest_file.write(&salt)?;
    dest_file.write(&nonce)?;

    info!(
        "Writing encrypted data of file {:?} to {:?}",
        source_path, dest_path
    );
    let mut buffer = [0u8; BUFFER_LEN];
    loop {
        let read_count = source_file.read(&mut buffer)?;
        if read_count == BUFFER_LEN {
            let ciphertext = match stream_encryptor.encrypt_next(buffer.as_slice()) {
                Ok(ciphertext) => ciphertext,
                Err(e) => return Err(format!("failed to encrypt buffer: {}", e).into()),
            };
            dest_file.write(&ciphertext)?;
        } else {
            let ciphertext = match stream_encryptor.encrypt_last(&buffer[..read_count]) {
                Ok(ciphertext) => ciphertext,
                Err(e) => return Err(format!("failed to encrypt last buffer: {}", e).into()),
            };
            dest_file.write(&ciphertext)?;
            break;
        }
    }
    hash.zeroize();
    Ok(())
}
