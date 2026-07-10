#pragma once

#include <stdexcept>
#include <iostream> 
#include <stdint.h>
#include <string> // for strings in programm processes
#include <cstring> // bytes operations (memcopy /  )
#include <sodium.h>
#include <vector>
#include <array>

// consts
constexpr int SALT_SIZE  = crypto_pwhash_SALTBYTES;
constexpr int KEY_SIZE   = crypto_secretbox_KEYBYTES;
constexpr int NONCE_SIZE = crypto_secretbox_NONCEBYTES;

// custom types
using Salt  = std::array<unsigned char, SALT_SIZE>;
using Key   = std::array<unsigned char, KEY_SIZE>;
using Nonce = std::array<unsigned char, NONCE_SIZE>;

// sub-functions
Salt  generate_salt();
Nonce generate_nonce();
Key   derive_key(const std::string& password, const Salt& salt);
std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext,  const Key& key, const Nonce& nonce);
std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext, const Key& key, const Nonce& nonce);
std::string generate_password(size_t len, bool use_lowercase = true, bool use_uppercase = true, bool use_digits = true, bool use_special = true);

// custom exceptions
struct KeyDerivationError      : std::runtime_error { using std::runtime_error::runtime_error; };
struct EncryptionError         : std::runtime_error { using std::runtime_error::runtime_error; };
struct DecryptionError         : std::runtime_error { using std::runtime_error::runtime_error; };
struct PasswordGenerationError : std::runtime_error { using std::runtime_error::runtime_error; };
struct SodiumInitError         : std::runtime_error { using std::runtime_error::runtime_error; };

// clases / PODs
struct PasswordParameters
{
    size_t length = 20;

    bool use_lowercase = true;
    bool use_uppercase = true;
    bool use_digits    = true;
    bool use_special   = true;

    void validate() const;
    size_t min_length() const; 

};

class Credentials
{
protected:
    char service[64];
    char login[64];
    char password[64];

public:
    friend std::ostream& operator<<(std::ostream& os, const Credentials& cred);
};