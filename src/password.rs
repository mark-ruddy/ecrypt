use argon2::{password_hash::PasswordHasher, Argon2};
use rpassword::prompt_password;
use std::error::Error;

pub fn get_from_user() -> Result<String, std::io::Error> {
    prompt_password("Encryption password: ")
}

pub fn get_argon_hash_of_password(password: &str, salt: &str) -> Result<String, Box<dyn Error>> {
    let argon2 = Argon2::default();
    let hash = match argon2.hash_password(password.as_bytes(), salt) {
        Ok(hash) => hash.to_string(),
        Err(e) => return Err(format!("Failed to hash password: {}", e).into()),
    };
    Ok(hash)
}
