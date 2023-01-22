use super::{
    utils::fill_hash_and_salt_from_password, BUFFER_LEN, ENCRYPTED_SUFFIX, HASH_STORED_SIZE,
    NONCE_SIZE, SALT_SIZE,
};
use chacha20poly1305::{aead::stream, KeyInit, XChaCha20Poly1305};
use log::{debug, info};
use rand::{rngs::OsRng, RngCore};
use std::{
    error::Error,
    fs::File,
    io::{Read, Write},
    str,
};
use walkdir::WalkDir;
use zeroize::Zeroize;

pub fn encrypt_file(
    source_path: &str,
    dest_path: &str,
    password: &str,
) -> Result<(), Box<dyn Error>> {
    let mut nonce = [0u8; NONCE_SIZE];
    let mut hash = [0u8; HASH_STORED_SIZE];
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut nonce);
    fill_hash_and_salt_from_password(password, &mut hash, &mut salt)?;

    debug!("Nonce is: {}", String::from_utf8_lossy(&nonce));
    debug!("Hash is: {}", String::from_utf8_lossy(&hash));
    debug!("Salt is: {}", String::from_utf8_lossy(&salt));

    let aead = XChaCha20Poly1305::new(hash.as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    let mut source_file = File::open(source_path)?;
    let mut dest_file = File::create(dest_path)?;

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
        } else if read_count == 0 {
            break;
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

pub fn encrypt_dir(
    source_path: &str,
    dest_path: &str,
    password: &str,
) -> Result<(), Box<dyn Error>> {
    for entry in WalkDir::new(source_path) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => return Err(format!("failure iterating over directory entry: {}", e).into()),
        };
        let md = entry.metadata()?;
        if md.is_dir() {
            continue;
        }
        let entry_path = match entry.path().to_str() {
            Some(entry_path) => entry_path,
            None => return Err("directory entry name is not valid unicode".into()),
        };

        // create new dir, write encrypted files to it

        let dest_path = format!("{}{}", entry_path, ENCRYPTED_SUFFIX);
        match encrypt_file(entry_path, &dest_path, password) {
            Ok(()) => (),
            Err(e) => return Err(format!("failure encrypting directory entry: {}", e).into()),
        }

        println!("{:?}", entry);
        println!("{}", entry.path().display());
    }
    Ok(())
}
