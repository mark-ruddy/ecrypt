use rpassword::prompt_password;

pub fn get_from_user(encryption: bool) -> Result<String, std::io::Error> {
    if encryption {
        prompt_password("Encryption password: ")
    } else {
        prompt_password("Decryption password: ")
    }
}
