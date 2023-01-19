use aes_gcm::{
    aead::{stream, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon_hash_password::create_hash_and_salt;
use generic_array::{typenum::U16, GenericArray};
use rand_core::RngCore;
use std::{error::Error, fs::File, io::Write};

fn encrypt_file(source_path: &str, dest_path: &str, password: &str) -> Result<(), Box<dyn Error>> {
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let parsed_nonce: Nonce<U16> = GenericArray::clone_from_slice(nonce.as_slice());

    let (hash, salt): (String, String) = create_hash_and_salt(password)?;
    let hash_vec = hash.into_bytes();
    let aead = Aes256Gcm::new(hash_vec[..32].as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    let mut source_file = File::open(source_path)?;
    let mut dest_file = File::open(dest_path)?;

    dest_file.write(&salt.into_bytes())?;
    dest_file.write(&nonce)?;

    const BUFFER_LEN: usize = 500;
    let mut buffer = [0u8; BUFFER_LEN];

    loop {
        let read_count = source_file.read(&mut buffer)?;
    }

    Ok(())
}
