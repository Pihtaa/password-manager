#pragma once


#include "password_manager\exceptions.h"
#include "password_manager\sodium_allocator.h"

#include <cstdint>
#include <string> // for strings in programm processes
#include <cstring> // bytes operations (memcopy /  )
#include <sodium.h>
#include <vector>
#include <array>
#include <iostream>


template <size_t N>
class SecureData
{
private:
    secure_vector<unsigned char> m_data;

public:
    SecureData() : m_data(N) {}

    SecureData(const SecureData&) = delete;
    SecureData& operator=(const SecureData&) = default;

    SecureData(SecureData&& other) = default;
    SecureData& operator=(SecureData&& other) = default;
    SecureData(secure_vector<unsigned char>&& vec)
    {
        if(vec.size() != N)
        {
            throw SecureDataVecSizeError("Secure data: wrong size of vector to convert.");
        }
        m_data = std::move(vec);
    }

    unsigned char* data() noexcept    { return m_data.data(); }
    const unsigned char* data() const noexcept { return m_data.data(); }
    size_t size() const noexcept      { return N; }
};

// consts
constexpr int SALT_SIZE  = crypto_pwhash_SALTBYTES;
constexpr int KEY_SIZE   = crypto_secretbox_KEYBYTES;
constexpr int NONCE_SIZE = crypto_secretbox_NONCEBYTES;

// custom types
using Salt  = SecureData<SALT_SIZE>;
using Key   = SecureData<KEY_SIZE>;
using Nonce = SecureData<NONCE_SIZE>;



class ICryptoEngine
{
public:
    virtual Salt  generate_salt()  = 0;
    virtual Nonce generate_nonce() = 0;
    virtual Key   derive_key(const secure_string& password, const Salt& salt) = 0;
    virtual secure_vector<unsigned char> encrypt(const secure_vector<unsigned char>& plaintext,  const Key& key, const Nonce& nonce) = 0;
    virtual secure_vector<unsigned char> decrypt(const secure_vector<unsigned char>& ciphertext, const Key& key, const Nonce& nonce) = 0;

    virtual ~ICryptoEngine() = default;
};


class LibsodiumCryptoEngine : public ICryptoEngine
{
public:
    Salt  generate_salt()  override;
    Nonce generate_nonce() override;
    Key   derive_key(const secure_string& password, const Salt& salt) override;
    secure_vector<unsigned char> encrypt(const secure_vector<unsigned char>& plaintext,  const Key& key, const Nonce& nonce) override;
    secure_vector<unsigned char> decrypt(const secure_vector<unsigned char>& ciphertext, const Key& key, const Nonce& nonce) override;

    LibsodiumCryptoEngine()
    {
        if(sodium_init() < 0)
        {
            throw SodiumInitError("Sodium initialization error.");
        }
    }
};