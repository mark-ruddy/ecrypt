use super::{BUFFER_LEN, HASH_START_INDEX, HASH_STORED_SIZE, NONCE_SIZE, SALT_SIZE};
use argon_hash_password::{hash_and_verify, parse_saltstring};
use chacha20poly1305::{aead::stream, KeyInit, XChaCha20Poly1305};
use log::info;
use std::{
    error::Error,
    fs::File,
    io::{Read, Write},
    str,
};
use zeroize::Zeroize;

pub fn decrypt_file(
    source_path: &str,
    dest_path: &str,
    password: &str,
) -> Result<(), Box<dyn Error>> {
    let mut source_file = File::open(source_path)?;
    let mut salt = [0u8; SALT_SIZE];
    let mut nonce = [0u8; NONCE_SIZE];

    let salt_count = source_file.read(&mut salt)?;
    if salt_count != salt.len() {
        return Err(format!("failure reading salt from start of source file").into());
    }

    let nonce_count = source_file.read(&mut nonce)?;
    if nonce_count != nonce.len() {
        return Err(format!("failure reading nonce from start of source file").into());
    }

    let saltstring = parse_saltstring(str::from_utf8(&salt)?)?;
    let mut hash = hash_and_verify(password, saltstring)?;
    let hash_bytes = hash.as_bytes();
    let hash_bytes_sized = &hash_bytes[HASH_START_INDEX..HASH_START_INDEX + HASH_STORED_SIZE];

    info!("Nonce is: {}", String::from_utf8_lossy(&nonce));
    info!("Nonce is: {:?}", &nonce);
    info!("Salt is len {}: {}", salt.len(), str::from_utf8(&salt)?);
    info!("Hash is: {}", String::from_utf8_lossy(hash_bytes_sized));

    let aead = XChaCha20Poly1305::new(hash_bytes_sized.as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

    let mut dest_file = File::create(dest_path)?;
    const BUFFER_LEN_DEC: usize = BUFFER_LEN + 16;
    let mut buffer = [0u8; BUFFER_LEN_DEC];
    loop {
        let read_count = source_file.read(&mut buffer)?;
        println!("buffer: {}", String::from_utf8_lossy(buffer.as_slice()));
        if read_count == BUFFER_LEN_DEC {
            let plaintext = match stream_decryptor.decrypt_next(buffer.as_slice()) {
                Ok(plaintext) => plaintext,
                Err(e) => return Err(format!("failed to decrypt buffer: {}", e).into()),
            };
            dest_file.write(&plaintext)?;
        } else if read_count == 0 {
            break;
        } else {
            let plaintext = match stream_decryptor.decrypt_last(buffer.as_slice()) {
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
