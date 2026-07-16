#pragma once


#include "password_manager\exceptions.h"

#include <cstdint>
#include <string> // for strings in programm processes
#include <cstring> // bytes operations (memcopy /  )
#include <sodium.h>
#include <vector>
#include <array>


template <size_t N>
class SecureData
{
private:
    std::array<unsigned char, N> m_data {};

public:
    SecureData() = default;
    ~SecureData()
    {
        sodium_memzero(m_data.data(), N);
    }
    
    SecureData(const SecureData&) = delete;
    SecureData& operator=(const SecureData&) = delete;

    SecureData(SecureData&& other) noexcept // std::move
    {
        m_data = other.m_data;
        sodium_memzero(other.m_data.data(), N);
    }

    SecureData(std::vector<unsigned char>& vec)
    {
        if(vec.size() != N) 
        {
            throw std::invalid_argument("Vector size doesnt match size of SecureData.");
        }
        std::copy(vec.begin(), vec.end(), m_data.begin());
        sodium_memzero(vec.data(), vec.size());
    }

    SecureData(std::vector<unsigned char>&& vec)
    {
        if(vec.size() != N) 
        {
            throw std::invalid_argument("Vector size doesnt match size of SecureData.");
        }
        std::copy(vec.begin(), vec.end(), m_data.begin());
        sodium_memzero(vec.data(), vec.size());
    }

    SecureData& operator=(std::vector<unsigned char>&& vec)
    {
        if(vec.size() != N) 
        {
            throw std::invalid_argument("Vector size doesnt match size of SecureData.");
        }
        std::copy(vec.begin(), vec.end(), m_data.data());
        sodium_memzero(vec.data(), vec.size());
        return *this;
    }

    SecureData& operator=(std::vector<unsigned char>& vec)
    {
        if(vec.size() != N) 
        {
            throw std::invalid_argument("Vector size doesnt match size of SecureData.");
        }
        std::copy(vec.begin(), vec.end(), m_data,data());
        sodium_memzero(vec.data(), vec.size());
        return *this;
    }

    SecureData& operator=(SecureData&& other) noexcept {
        if (this != &other) {
            sodium_memzero(m_data.data(), N);
            m_data = other.m_data;
            sodium_memzero(other.m_data.data(), N); 
        }
        return *this;
    }



    unsigned char* data()             { return m_data.data(); }
    const unsigned char* data() const { return m_data.data(); }
    constexpr size_t size() const     { return N; }
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
    virtual Key   derive_key(std::string& password, const Salt& salt) = 0;
    virtual std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext,  const Key& key, const Nonce& nonce) = 0;
    virtual std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext, const Key& key, const Nonce& nonce) = 0;

    virtual ~ICryptoEngine() = default;
};


class LibsodiumCryptoEngine : public ICryptoEngine
{
public:
    Salt  generate_salt()  override;
    Nonce generate_nonce() override;
    Key   derive_key(std::string& password, const Salt& salt) override;
    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext,  const Key& key, const Nonce& nonce) override;
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext, const Key& key, const Nonce& nonce) override;

    LibsodiumCryptoEngine()
    {
        sodium_init();
    }
};