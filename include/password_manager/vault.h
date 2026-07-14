#pragma once

#include<filesystem> // scince C++17. Check is file empty or not
#include<array>
#include<sodium.h>
#include<fstream>
#include"password_manager\crypto.h"

using Hashed_password_str = std::array<char, crypto_pwhash_STRBYTES>;

struct VaultData
{
    Hashed_password_str hashed_password_str;
    //Salt salt;
};

// Interface for Vault with master-password
class IVault 
{
public:
    virtual void hash_and_save_password(const std::string& password) = 0;
    virtual bool verify_password(const std::string& password) = 0;


    virtual ~IVault() = default;
}; 
//

class VaultBinFile : public IVault
{
private:
    unsigned long long OPSLIMIT = crypto_pwhash_OPSLIMIT_MODERATE;
    unsigned long long MEMLIMIT = crypto_pwhash_MEMLIMIT_MODERATE;
    std::string filename;

    void save_data(const VaultData& vault_data);
    VaultData load_data();
    bool data_exists() const; 


public:
    void set_opslimit(unsigned long long opslimit);
    void set_memlimit(unsigned long long memlimit);

    explicit VaultBinFile(const std::string& filename) : filename(filename) {}
    explicit VaultBinFile(const std::string& filename, unsigned long long opslimit, unsigned long long memlimit) 
        : filename(filename), OPSLIMIT(opslimit), MEMLIMIT(memlimit) {}

    void hash_and_save_password(const std::string& password) override;
    bool verify_password(const std::string& password) override;


};