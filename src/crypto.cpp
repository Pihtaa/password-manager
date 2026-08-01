#include "password_manager/crypto.h"

#include <cstring>
#include <iostream>
#include <array>


Salt  LibsodiumCryptoEngine::generate_salt()
{
    Salt salt_to_return;
    randombytes_buf(salt_to_return.data(), SALT_SIZE);
    return salt_to_return;
}


Nonce LibsodiumCryptoEngine::generate_nonce()
{
    Nonce nonce_to_return;
    randombytes_buf(nonce_to_return.data(), NONCE_SIZE);
    return nonce_to_return;
}


Key   LibsodiumCryptoEngine::derive_key(const secure_string& password, const Salt& salt)
{
    Key key_to_return;
    if(crypto_pwhash
        (key_to_return.data(), (unsigned long long)KEY_SIZE, password.data(), password.length(), salt.data(), 
        m_opslimit, m_memlimit, crypto_pwhash_ALG_ARGON2ID13)
      != 0)
    {
        throw KeyDerivationError("Key derivation failed. Out of memory / system collapse.");
    }
    return key_to_return;
}


secure_vector<unsigned char> LibsodiumCryptoEngine::encrypt(const secure_vector<unsigned char>& plaintext,  const Key& key, const Nonce& nonce)
{
    secure_vector<unsigned char> vector_to_return(static_cast<size_t>(crypto_secretbox_MACBYTES) + plaintext.size()); // crypto_secretbox_MACBYTES - libsodium constant
    if(crypto_secretbox_easy
        (vector_to_return.data(), plaintext.data(), static_cast<unsigned long long>(plaintext.size()), nonce.data(), key.data())
        != 0)
    {
        throw EncryptionError("Encryption failed. Out of memory / system collapse");
    }
    return vector_to_return;
}


secure_vector<unsigned char> LibsodiumCryptoEngine::decrypt(const secure_vector<unsigned char>& ciphertext, const Key& key, const Nonce& nonce)
{
    if(ciphertext.size() < crypto_secretbox_MACBYTES)
    {
        throw DecryptionError("Decryption error. Ciphertext is too small.");
    }

    secure_vector<unsigned char> vector_to_return(ciphertext.size() - static_cast<size_t>(crypto_secretbox_MACBYTES));
    
    if(crypto_secretbox_open_easy
        (vector_to_return.data(), ciphertext.data(), static_cast<unsigned long long>(ciphertext.size()), nonce.data(), key.data())
        != 0)
    {
        throw DecryptionError("Decryption error. Ciphertext forged.");
    }

    return vector_to_return;
}


void LibsodiumCryptoEngine::set_opslimit(unsigned long long opslimit)
{
    m_opslimit = opslimit;
}

void LibsodiumCryptoEngine::set_memlimit(unsigned long long memlimit)
{
    m_memlimit = memlimit;
}



void LibsodiumCryptoEngine::change_security_level(SecurityLevel sec_level)
{
    m_cur_sec_level = sec_level;
    switch(sec_level)
    {
    case SecurityLevel::Low:
        set_opslimit(crypto_pwhash_OPSLIMIT_MIN);
        set_memlimit(crypto_pwhash_MEMLIMIT_MIN);
        break;
    case SecurityLevel::Moderate:
        set_opslimit(crypto_pwhash_OPSLIMIT_MODERATE);
        set_memlimit(crypto_pwhash_MEMLIMIT_MODERATE);
        break;
    case SecurityLevel::High:
        set_opslimit(crypto_pwhash_OPSLIMIT_SENSITIVE);
        set_memlimit(crypto_pwhash_MEMLIMIT_SENSITIVE);
        break;
    }
}


LibsodiumCryptoEngine::LibsodiumCryptoEngine(SecurityLevel sec_level)
{
    m_cur_sec_level = sec_level;
    change_security_level(sec_level);
    if(sodium_init() < 0)
    {
        throw SodiumInitError("Sodium initialization error.");
    }
}


SecurityLevel LibsodiumCryptoEngine::get_security_level() const
{
    return m_cur_sec_level;
}