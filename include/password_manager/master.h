#pragma once

#include<filesystem> // scince C++17. Check is file empty or not
#include<array>
#include<sodium.h>
#include<fstream>
#include"password_manager\crypto.h"

using Hashed_password_str = std::array<char, crypto_pwhash_STRBYTES>;

struct MasterPasswordData
{
    Hashed_password_str hashed_password_str;
};

enum class SecurityLevel
{
    Low,
    Moderate,
    High
};


// Interface for Vault with master-password
class IMasterStorage 
{
public:
    virtual bool initialize_password_with_approvement(const secure_string& password) = 0;
    virtual void hash_and_save_password(const secure_string& password) = 0;
    virtual bool verify_password(const secure_string& password) const = 0;
    virtual bool data_exists() const = 0;
    virtual bool change_security_level(const secure_string& password, SecurityLevel sec_level) = 0;

    virtual ~IMasterStorage() = default;
}; 
//

class MasterStorageBinFile : public IMasterStorage
{
private:
    int min_required_length = 12;

    unsigned long long OPSLIMIT = crypto_pwhash_OPSLIMIT_MODERATE;
    unsigned long long MEMLIMIT = crypto_pwhash_MEMLIMIT_MODERATE;
    std::string filename;

    void save_data(const MasterPasswordData& vault_data);
    MasterPasswordData load_data() const;
    void set_opslimit(unsigned long long opslimit);
    void set_memlimit(unsigned long long memlimit);
    bool is_strong_password(const secure_string& password);

public:
    explicit MasterStorageBinFile(const std::string& filename) : filename(filename) {}
    explicit MasterStorageBinFile(const std::string& filename, unsigned long long opslimit, unsigned long long memlimit) 
        : filename(filename), OPSLIMIT(opslimit), MEMLIMIT(memlimit) {}

    bool initialize_password_with_approvement(const secure_string& password) override;
    void hash_and_save_password(const secure_string& password) override;
    bool verify_password(const secure_string& password) const override;
    bool data_exists() const override; 
    bool change_security_level(const secure_string& password, SecurityLevel sec_level) override;


};