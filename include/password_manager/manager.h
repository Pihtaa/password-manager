#pragma once

#include "password_manager/password_gen.h"
#include "password_manager/vault.h"
#include "password_manager/master.h"

class PasswordManagerApp
{
private:
    std::unique_ptr<IMasterStorage> m_master_storage;
    std::unique_ptr<IPasswordStrengthChecker> m_checker;
    std::unique_ptr<IPasswordGenerator> m_password_generator;
    std::string m_vault_filename;
    std::unique_ptr<Vault> m_vault; // nullptr before succesfull login
    
    std::unique_ptr<IVaultStorage> m_vault_storage;
    std::unique_ptr<ICryptoEngine> m_crypto_engine;
    std::unique_ptr<ICredentialsFormatter> m_formatter;

public:
    PasswordManagerApp(std::unique_ptr<IMasterStorage> master_storage,
                       std::unique_ptr<IPasswordStrengthChecker> checker,
                       std::unique_ptr<IVaultStorage> vault_storage,
                       std::unique_ptr<ICryptoEngine> crypto_engine,
                       std::unique_ptr<ICredentialsFormatter> formatter,
                       std::unique_ptr<IPasswordGenerator> password_generator,
                       std::string vault_filename);


    bool is_first_run() const;
    bool setup_master_password(const secure_string& password);


    bool login(const secure_string& password);
    bool is_logged_in() const;

    //accessable only after master password validation
    const secure_vector<Credentials>& get_credentials() const;
    void add_credentials(secure_string service, secure_string login, secure_string password);
    void remove_credentials(size_t index);
    void change_security_level(const secure_string& master_password, SecurityLevel sec_level);

    void save();
    void logout();
};