use super::{
    utils::fill_hash_and_salt_from_password, BUFFER_LEN, ENCRYPTED_SUFFIX, HASH_STORED_SIZE,
    NONCE_SIZE, SALT_SIZE,
};
use chacha20poly1305::{aead::stream, KeyInit, XChaCha20Poly1305};
use flate2::{write::GzEncoder, Compression};
use log::{debug, info};
use rand::{rngs::OsRng, RngCore};
use std::{
    error::Error,
    fs::File,
    io::{Read, Write},
    str,
};
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
    compress: bool,
) -> Result<(), Box<dyn Error>> {
    let mut archive_path = format!("{}.tar", source_path);
    if compress {
        archive_path = format!("{}.tgz", source_path);
    }
    let archive = File::create(archive_path)?;
    if compress {
        let enc = GzEncoder::new(archive, Compression::default());
        let mut tar = tar::Builder::new(enc);
        tar.append_dir_all(source_path, source_path)?;
    } else {
        let enc = GzEncoder::new(archive, Compression::none());
        let mut tar = tar::Builder::new(enc);
        tar.append_dir_all(source_path, source_path)?;
    }
    // encrypt_file(&compressed_archive_path, dest_path, password);
    Ok(())
}
