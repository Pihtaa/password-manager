#include"password_manager\crypto.h"

#include<memory>
#include<iostream>
#include<nlohmann/json.hpp>
#include<fstream>
#include<filesystem>


using json = nlohmann::json;


class Credentials
{
private:
    std::string service;
    std::string login;
    std::string password;

public:
    friend std::ostream& operator<<(std::ostream& os, const Credentials& cred);
};


struct RawVaultData
{
    Salt salt;
    Nonce nonce;
    std::vector<unsigned char> ciphertext;
};


class IVaultStorage // interface that interacts only with raw chiphred data
{
public:
    virtual bool vault_exists() const = 0;
    virtual void save_vault(const RawVaultData& raw_vault_data) = 0;
    virtual RawVaultData load_vault() = 0;

    virtual ~IVaultStorage() = default;
};

class VaultStorageJson : public IVaultStorage
{
private:
    std::string bin_to_base64(const void* data, size_t size);
    std::vector<unsigned char> base64_to_bin(std::string base64_str);
    std::string m_filename;
public:
    bool vault_exists() const override;
    void save_vault(const RawVaultData& raw_vault_data) override;
    RawVaultData load_vault() override;

    explicit VaultStorageJson(std::string filename) : m_filename(filename) {}
};


class Vault
{
private:
    std::unique_ptr<IVaultStorage> m_storage;
    std::vector<Credentials> m_credentials;
    bool m_is_changed = false;
    Key m_session_key; // хранит ключ пока открыт

public:
    explicit Vault(std::unique_ptr<IVaultStorage> storage, Key session_key)
        : m_storage(std::move(storage)), m_session_key(std::move(session_key)) {}
    
    void load();
    void save();
    void add(Credentials credentials);
    void remove(size_t number);
    
    ~Vault();
};
