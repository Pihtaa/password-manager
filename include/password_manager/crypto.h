#pragma once


#include "password_manager\exceptions.h"

#include <cstdint>
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
