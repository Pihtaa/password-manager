#pragma once

#include "password_manager/crypto.h"
#include "password_manager/sodium_allocator.h"

#include <memory>
#include <iostream>
#include <nlohmann/json.hpp>
#include <fstream>
#include <filesystem>
#include <cstdint>


using json = nlohmann::json;



class Credentials
{
public:
    secure_string service;
    secure_string login;
    secure_string password;

    
    Credentials(secure_string s, secure_string l, secure_string p)
            : service(std::move(s)), 
            login(std::move(l)), 
            password(std::move(p)) {}


    Credentials(const Credentials&) = delete;
    Credentials& operator=(const Credentials&) = delete;

    Credentials(Credentials&&) noexcept = default;
    Credentials& operator=(Credentials&&) noexcept = default;

    friend std::ostream& operator<<(std::ostream& os, const Credentials& cred);
};


struct RawVaultData
{
    Salt salt;
    Nonce nonce;
    secure_vector<unsigned char> ciphertext;
};


class IVaultStorage // interface that interacts only with raw chiphred data
{
public:
    virtual bool vault_exists() const = 0;
    virtual void save_raw_data(const RawVaultData& raw_vault_data) = 0;
    virtual RawVaultData load_vault() const = 0;

    virtual ~IVaultStorage() = default;
};

class VaultStorageJson final : public IVaultStorage
{
private:
    std::string m_filename;

    secure_string bin_to_base64(const void* data, size_t size) const;
    secure_vector<unsigned char> base64_to_bin(std::string& base64_str) const;

public:
    bool vault_exists() const override;
    void save_raw_data(const RawVaultData& raw_vault_data) override;
    RawVaultData load_vault() const override;

    explicit VaultStorageJson(std::string filename) : m_filename(std::move(filename)) {}
};

class ICredentialsFormatter
{
public:
    virtual secure_vector<unsigned char> encode(const secure_vector<Credentials>& cred_vector_for_formatting) = 0; 
    // method to encode and format input str - preparetion before encryption
    virtual secure_vector<Credentials> decode(const secure_vector<unsigned char>& decrypted_data) = 0;
    // method to call afted decryption to get real data from encoded data
};

class JsonCredentialsFormatter final : public ICredentialsFormatter
{
public:
    secure_vector<unsigned char> encode(const secure_vector<Credentials>& cred_vector_for_formatting) override;
    secure_vector<Credentials> decode(const secure_vector<unsigned char>& decrypted_data) override;
};


class Vault
{
private:
    std::unique_ptr<IVaultStorage> m_storage;
    std::unique_ptr<ICryptoEngine> m_crypto_engine;
    std::unique_ptr<ICredentialsFormatter> m_formatter;    

    std::string m_sec_level_filename = "security_level.bin";
    secure_vector<Credentials> m_credentials;
    Key m_session_key;
    Salt m_salt; 

public:
    explicit Vault(std::unique_ptr<IVaultStorage> storage, std::unique_ptr<ICryptoEngine> crypto_engine,
        std::unique_ptr<ICredentialsFormatter> cred_formatter, const secure_string& password);
    
    const secure_vector<Credentials>& get_credentials() const { return m_credentials; }
    void rederive_key(const secure_string& new_master_password);
    void change_key_derivation_security_level(const secure_string& password, SecurityLevel sec_level);
    void save();
    void add(Credentials&& credentials);
    void remove(size_t pos);
};


struct VaultData
{
    std::string file_name;
    uint64_t time_added;
};


class IMultiVaultStorage
{
public:
    virtual bool vault_exists() const = 0;
    virtual std::vector<VaultData> load_vault() const = 0;
    virtual void add_new_vault_data(const VaultData& vault_data) = 0;
    virtual bool delete_vault_data(const std::size_t index) = 0;
    virtual void save() = 0; // must be implicitly called in the every usage end of IMultiVaultStorage

    virtual ~IMultiVaultStorage() = default;
};


class MultiVaultJsonStorage : public IMultiVaultStorage
{
private:
    std::string m_filename;
    std::vector<VaultData> m_vaults_data;
public:
    explicit MultiVaultJsonStorage(const std::string& filename = "vaults.json");
    bool vault_exists() const override;
    std::vector<VaultData> load_vault() const override;
    void add_new_vault_data(const VaultData& vault_data) override;
    bool delete_vault_data(const std::size_t index) override;
    void save() override;
};