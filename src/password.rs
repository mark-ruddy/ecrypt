use rpassword::prompt_password;

pub fn get_from_user() -> Result<String, std::io::Error> {
    prompt_password("Encryption password: ")
}
