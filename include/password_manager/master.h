#pragma once

#include<filesystem> // Check is file empty or not
#include<array>
#include<sodium.h>
#include<fstream>
#include"password_manager\crypto.h"
#include"password_manager\sodium_allocator.h"
#include"password_manager\sec_level.h"

using Hashed_password_str = std::array<char, crypto_pwhash_STRBYTES>;

struct MasterPasswordData
{
    Hashed_password_str hashed_password_str;
};


class IMasterStorage 
{
public:
    virtual void hash_and_save_password(const secure_string& password) = 0;
    virtual bool verify_password(const secure_string& password) const = 0;
    virtual bool data_exists() const = 0;
    virtual void change_security_level(SecurityLevel sec_level) = 0;

    virtual ~IMasterStorage() = default;
}; 


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

public:
    explicit MasterStorageBinFile(const std::string& filename) : filename(filename) {}
    explicit MasterStorageBinFile(const std::string& filename, unsigned long long opslimit, unsigned long long memlimit) 
        : filename(filename), OPSLIMIT(opslimit), MEMLIMIT(memlimit) {}

    void hash_and_save_password(const secure_string& password) override;
    bool verify_password(const secure_string& password) const override;
    bool data_exists() const override; 
    void change_security_level(SecurityLevel sec_level) override;
};


class IPasswordStrengthChecker
{
public:
    virtual bool is_strong(const secure_string& password) const = 0;
    virtual std::string requirements_description() const = 0;

    virtual ~IPasswordStrengthChecker() = default;
};


class BasicPasswordStrengthChecker : public IPasswordStrengthChecker
{
private:
    size_t m_min_length;

public:
    explicit BasicPasswordStrengthChecker(size_t min_length = 12) 
        : m_min_length(min_length) {}
        
    bool is_strong(const secure_string& password) const override;
    std::string requirements_description() const override;
};