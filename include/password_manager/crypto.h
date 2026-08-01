#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <sodium.h>

#include "password_manager/sec_level.h"
#include "password_manager/exceptions.h"
#include "password_manager/sodium_allocator.h"


template <std::size_t N>
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

    bool operator==(const SecureData& other) const noexcept 
    {
       return m_data == other.m_data; 
    }
    
    auto operator<=>(const SecureData& other) const noexcept
    {
        return m_data <=> other.m_data;
    }

    unsigned char* data() noexcept    { return m_data.data(); }
    const unsigned char* data() const noexcept { return m_data.data(); }
    size_t size() const noexcept      { return N; }
};

// consts
constexpr std::size_t SALT_SIZE  = crypto_pwhash_SALTBYTES;
constexpr std::size_t KEY_SIZE   = crypto_secretbox_KEYBYTES;
constexpr std::size_t NONCE_SIZE = crypto_secretbox_NONCEBYTES;

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
    virtual void change_security_level(SecurityLevel sec_level) = 0;
    virtual SecurityLevel get_security_level() const = 0;
    virtual ~ICryptoEngine() = default;
};


class LibsodiumCryptoEngine : public ICryptoEngine
{
private:
    unsigned long long m_opslimit;
    unsigned long long m_memlimit;

    void set_opslimit(unsigned long long opslimit);
    void set_memlimit(unsigned long long memlimit);

    SecurityLevel m_cur_sec_level;
public:
    LibsodiumCryptoEngine(SecurityLevel sec_level = SecurityLevel::Moderate);

    Salt  generate_salt()  override;
    Nonce generate_nonce() override;
    Key   derive_key(const secure_string& password, const Salt& salt) override;
    secure_vector<unsigned char> encrypt(const secure_vector<unsigned char>& plaintext,  const Key& key, const Nonce& nonce) override;
    secure_vector<unsigned char> decrypt(const secure_vector<unsigned char>& ciphertext, const Key& key, const Nonce& nonce) override;
    void change_security_level(SecurityLevel sec_level) override;
    SecurityLevel get_security_level() const override;
};