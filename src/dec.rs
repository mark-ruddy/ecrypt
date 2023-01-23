use super::{
    utils::{create_new, fill_hash_from_salt_and_password},
    BUFFER_LEN, HASH_STORED_SIZE, NONCE_SIZE, SALT_SIZE,
};
use chacha20poly1305::{aead::stream, KeyInit, XChaCha20Poly1305};
use flate2::read::GzDecoder;
use log::{debug, info};
use std::{
    error::Error,
    fs::File,
    io::{Read, Write},
    str,
};
use tar::Archive;
use zeroize::Zeroize;

pub fn decrypt_file(
    source_path: &str,
    dest_path: &str,
    password: &str,
) -> Result<(), Box<dyn Error>> {
    let mut salt = [0u8; SALT_SIZE];
    let mut nonce = [0u8; NONCE_SIZE];

    let mut source_file = File::open(source_path)?;
    let mut dest_file = create_new(dest_path)?;

    let salt_count = source_file.read(&mut salt)?;
    if salt_count != salt.len() {
        return Err(format!("failure reading salt from start of source file").into());
    }

    let nonce_count = source_file.read(&mut nonce)?;
    if nonce_count != nonce.len() {
        return Err(format!("failure reading nonce from start of source file").into());
    }

    let mut hash = [0u8; HASH_STORED_SIZE];
    fill_hash_from_salt_and_password(password, str::from_utf8(&salt)?, &mut hash)?;

    debug!("Nonce is: {}", String::from_utf8_lossy(&nonce));
    debug!("Salt is: {}", str::from_utf8(&salt)?);
    debug!("Hash is: {}", String::from_utf8_lossy(&hash));

    let aead = XChaCha20Poly1305::new(hash.as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

    info!(
        "Writing decrypted data of file {:?} to {:?}",
        source_path, dest_path
    );
    const BUFFER_LEN_DEC: usize = BUFFER_LEN + 16;
    let mut buffer = [0u8; BUFFER_LEN_DEC];
    loop {
        let read_count = source_file.read(&mut buffer)?;
        if read_count == BUFFER_LEN_DEC {
            let plaintext = match stream_decryptor.decrypt_next(buffer.as_slice()) {
                Ok(plaintext) => plaintext,
                Err(e) => return Err(format!("failed to decrypt buffer: {}", e).into()),
            };
            dest_file.write(&plaintext)?;
        } else if read_count == 0 {
            break;
        } else {
            let plaintext = match stream_decryptor.decrypt_last(&buffer[..read_count]) {
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

pub fn decrypt_dir(
    source_path: &str,
    dest_path: &str,
    password: &str,
) -> Result<(), Box<dyn Error>> {
    decrypt_file(&source_path, &dest_path, &password)?;

    info!("Unpacking tarball of decrypted directory: '{}'", dest_path);
    let decrypted_dir_tarball = File::open(dest_path)?;
    let dec = GzDecoder::new(decrypted_dir_tarball);
    let mut decrypted_dir_archive = Archive::new(dec);
    decrypted_dir_archive.unpack(".")?;
    Ok(())
}
