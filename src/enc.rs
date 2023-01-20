use argon_hash_password::create_hash_and_salt;
use chacha20poly1305::{aead::stream, KeyInit, XChaCha20Poly1305};
use log::info;
use rand::{rngs::OsRng, RngCore};
use std::{
    error::Error,
    fs::File,
    io::{Read, Write},
};
use zeroize::Zeroize;

pub fn encrypt_file(
    source_path: &str,
    dest_path: &str,
    password: &str,
) -> Result<(), Box<dyn Error>> {
    // Nonce total size will be 32, 19 bytes generated to start: https://docs.rs/aead/latest/aead/stream/struct.StreamBE32.html
    let mut nonce = [0u8; 19];
    OsRng.fill_bytes(&mut nonce);

    let (mut hash, mut salt): (String, String) = create_hash_and_salt(password)?;
    let hash_vec = hash.as_bytes();
    let aead = XChaCha20Poly1305::new(hash_vec[..32].as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    let mut source_file = File::open(source_path)?;
    let mut dest_file = File::create(dest_path)?;

    // Write the salt and the nonce to the start of the dest file
    info!("salt is: {}", &salt);
    info!("nonce is: {:?}", String::from_utf8(nonce.to_vec()));
    dest_file.write(&salt.as_bytes())?;
    dest_file.write(&nonce)?;

    const BUFFER_LEN: usize = 500;
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

    // remove secrets from memory after usage
    hash.zeroize();
    salt.zeroize();
    nonce.zeroize();

    Ok(())
}
