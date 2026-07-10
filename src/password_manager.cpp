#include "password_manager/password_manager.h"


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


std::string generate_password(const PasswordParameters& parameters)
{
    parameters.validate();
    const size_t min_len = parameters.min_length();

    static constexpr std::string_view lowercase = "abcdefghijklmnopqrstuvwxyz";
    static constexpr std::string_view uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static constexpr std::string_view digits    = "0123456789";
    static constexpr std::string_view special   = "!@#$%^&*()-_=+[]{}|;:,.<>?";

    std::string password;
    password.reserve(parameters.length);
    std::string pool;
    pool.reserve(lowercase.length() + uppercase.length() + digits.length() + special.length());

    if(parameters.use_lowercase)
    {
        pool += lowercase;
        password += lowercase[randombytes_uniform(static_cast<uint32_t>(lowercase.length()))];
    }
    if(parameters.use_uppercase)
    {
        pool += uppercase;
        password += uppercase[randombytes_uniform(static_cast<uint32_t>(uppercase.length()))];
    }
    if(parameters.use_digits)
    {
        pool += digits;
        password += digits[randombytes_uniform(static_cast<uint32_t>(digits.length()))];
    }
    if(parameters.use_special)
    {
        pool += special;
        password += special[randombytes_uniform(static_cast<uint32_t>(special.length()))];
    }
    

    for(size_t i = min_len; i < parameters.length; ++i)
    {
        uint32_t pool_len = static_cast<uint32_t>(pool.length());
        password.push_back(pool[randombytes_uniform(pool_len)]);
    }
    
    for(uint32_t i = static_cast<uint32_t>(parameters.length - 1); i > 0; --i)
    {
        std::swap(password[i], password[randombytes_uniform(i + 1)]);
    }

    return password;
}



std::ostream& operator<<(std::ostream& os, const Credentials& cred)
{
    os <<" Service:  "<< cred.service <<"\n" 
       <<" Login:    "<< cred.login <<"\n"
       <<" Password: "<< cred.password<<std::endl;
    return os;
}


void PasswordParameters::validate() const
{
    size_t min_len = static_cast<size_t>(use_lowercase) + static_cast<size_t>(use_uppercase) +
                        static_cast<size_t>(use_digits)    + static_cast<size_t>(use_special);
    if (min_len == 0)
    {
        throw std::invalid_argument("No symbol types selected.");
    }
    if (length < min_len)
    {
        throw std::invalid_argument("Length too short for selected groups.");
    }
    if (length > 64)
    {
        throw std::invalid_argument("Length too long.");
    }            
}

size_t PasswordParameters::min_length() const
{
    return static_cast<size_t>(use_lowercase) +
           static_cast<size_t>(use_uppercase) +
           static_cast<size_t>(use_digits)    +
           static_cast<size_t>(use_special);
}