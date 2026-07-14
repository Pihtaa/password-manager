#include "password_manager/crypto.h"


Salt  generate_salt()
{
    Salt salt_to_return;
    randombytes_buf(salt_to_return.data(), SALT_SIZE);
    return salt_to_return;
}


Nonce generate_nonce()
{
    Nonce nonce_to_return;
    randombytes_buf(nonce_to_return.data(), NONCE_SIZE);
    return nonce_to_return;
}


Key   derive_key(const std::string& password, const Salt& salt)
{
    Key key_to_return;
    if(crypto_pwhash
        (key_to_return.data(), (unsigned long long)KEY_SIZE, password.data(), password.length(), salt.data(), 
        crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_ALG_ARGON2ID13)
      != 0)
    {
        throw KeyDerivationError("Key derivation failed. Out of memory / system collapse.");
    }
    return key_to_return;
}


std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext,  const Key& key, const Nonce& nonce)
{
    std::vector<unsigned char> vector_to_return(static_cast<size_t>(crypto_secretbox_MACBYTES) + plaintext.size()); // crypto_secretbox_MACBYTES - libsodium constant
    if(crypto_secretbox_easy
        (vector_to_return.data(), plaintext.data(), static_cast<unsigned long long>(plaintext.size()), nonce.data(), key.data())
        != 0)
    {
        throw EncryptionError("Encryption failed. Out of memory / system collapse");
    }
    return vector_to_return;
}


std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext, const Key& key, const Nonce& nonce)
{
    if(ciphertext.size() < crypto_secretbox_MACBYTES)
    {
        throw DecryptionError("Decryption error. Ciphertext is too small.");
    }

    std::vector<unsigned char> vector_to_return(ciphertext.size() - static_cast<size_t>(crypto_secretbox_MACBYTES));
    
    if(crypto_secretbox_open_easy
        (vector_to_return.data(), ciphertext.data(), static_cast<unsigned long long>(ciphertext.size()), nonce.data(), key.data())
        != 0)
    {
        throw DecryptionError("Decryption error. Ciphertext forged.");
    }

    return vector_to_return;
}

