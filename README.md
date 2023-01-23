# ecrypt (Easy Encryption)
Tool to easily encrypt files or directories with an easy-to-use and opinionated CLI interface. The encryption/decryption process and the source code is transparent and easily understandable, see the [Under the Hood](#under-the-hood) section.

## Usage
### Install
The simplest way is: `cargo install ecrypt`

To build from source, you can clone the repo and build the release binary:

```
git clone https://github.com/tirax-lab/ecrypt
cd ecrypt
cargo build --release
sudo mv target/release/ecrypt /usr/local/bin
```

Use `--help` after any subcommand(e.g. `enc` for encrypt and `dec` for decrypt) to view all options. For example directory encryption supports the `-c/--compress` flag for tar gunzip compression.

### Encrypt a file or directory

```
$ ecrypt enc README.md
Encryption password: 
[2023-01-23T20:37:31Z INFO  ecrypt::enc] Writing encrypted data of file "README.md" to "README.md.encrypted"
[2023-01-23T20:37:31Z WARN  ecrypt::enc] The unencrypted file 'README.md' remains on disk, you can remove it manually or run ecrypt with the --remove/-r flag
```

A file `README.md.encrypted` will have been created with the encrypted contents.

### Decrypt a file

```
$ ecrypt dec README.md.encrypted 
Decryption password: 
[2023-01-23T20:39:11Z INFO  ecrypt::dec] Writing decrypted data of file "README.md.encrypted" to "README.md.decrypted"
```

A file `README.md.decrypted` will have been created with the decrypted contents.

### Decrypt a directory

```
$ ecrypt dec directory.encrypted_dir 
Decryption password: 
[2023-01-23T20:41:33Z INFO  ecrypt::dec] Writing decrypted data of file "directory.encrypted_dir" to "directory.decrypted"
[2023-01-23T20:41:33Z INFO  ecrypt::dec] Unpacking tarball of decrypted directory: 'directory.decrypted'
```

This will create 2 outputs - a `directory.decrypted` file which is the decrypted tarball, and the actual unencrypted directory itself `directory` will be there

## Under the Hood
This section documents how `ecrypt` handles file/directory encryption and decryption so you can evaluate if it is suitable for your security needs. For background see the article on Rust file encryption by [Sylvian Kerkour, the author of Black Hat Rust](https://kerkour.com/rust-file-encryption-chacha20poly1305-argon2):

### File Encryption

- User specifies the source file to be encrypted
- User provides a password with either the `-p` flag or to the password prompt
- The password is hashed using `argon`, with a salt being produced
- A nonce is generated with random bytes
- A 32 byte extract is taken from the hash and used as a key to the `chacha20poly1305` stream encryptor with the generated nonce
- The salt and nonce are written to the start of the output file which will have the `.encrypted` suffix
- The `chacha20poly1305` stream encryptor encrypts and writes chunks of bytes to the output file until the entire source file has been read
- The final result is a `file.encrypted` which has salt and a nonce at the beginning of the file and encrypted data after that

### File Decryption

- User specifies the source file to be decrypted, it may have the `.encrypted` suffix but this is not required
- User provides a password with either the `-p/--password` flag or to the password prompt
- The salt and the nonce are read from the start of the source file into Rust variables
- Using the provided password and the salt, the same hash that was used for encryption is produced and used as a key to the `chacha20poly1305` stream decryptor and the same nonce has been read from the file. If an incorrect password is provided this hash will be different and the decryption will fail.
- The `chacha20poly1305` stream decryptor decrypts and writes chunks of bytes to the output file, which will have a `.decrypted` suffix, until the entire source file has been read
- The final result is a `file.decrypted` which contains the plaintext

### Directory Encryption

- The directory is archived into a tarball, with optional compression by specifying the `-c/--compress` flag
- This tarball is then encrypted using file encryption and outputed to `directory.encrypted`
- The unencrypted tarball is then deleted, the user can specify `-r/--remove` to automatically delete the original non-tarball directory too

### Directory Decryption

- The encrypted tarball is decrypted first using file decryption
- The decrypted tarball is then unpacked/unarchived to the current working directory
- This results in both `directory.decrypted`(decrypted tarball) and `directory`(unencrypted directory) being produced
