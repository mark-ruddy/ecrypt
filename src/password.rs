use argon_hash_password::create_hash_and_salt;
use rpassword::prompt_password;
use std::error::Error;

pub fn get_from_user() -> Result<String, std::io::Error> {
    prompt_password("Encryption password: ")
}

/*
pub fn get_argon_hash_of_password(password: &str) -> Result<&str, Box<dyn Error>> {
    let (hash, salt) = create_hash_and_salt(password);
    Ok(())
}
*/
