#include "password_manager\manager.h"

PasswordManagerApp::PasswordManagerApp(std::unique_ptr<IMasterStorage> master_storage,
                       std::unique_ptr<IPasswordStrengthChecker> checker,
                       std::unique_ptr<IVaultStorage> vault_storage,
                       std::unique_ptr<ICryptoEngine> crypto_engine,
                       std::unique_ptr<ICredentialsFormatter> formatter,
                       std::unique_ptr<IPasswordGenerator> password_generator,
                       std::string vault_filename) 
                       : m_master_storage(std::move(master_storage)),
                       m_checker(std::move(checker)),
                       m_vault_storage(std::move(vault_storage)),
                       m_crypto_engine(std::move(crypto_engine)),
                       m_formatter(std::move(formatter)),
                       m_password_generator(std::move(password_generator)),
                       m_vault_filename(std::move(vault_filename)) {}


bool PasswordManagerApp::is_first_run() const
{
    return !m_master_storage->data_exists();
}


bool PasswordManagerApp::setup_master_password(const secure_string& password)
{
    if(! (m_checker->is_strong(password)))
    {
        return false;
    }
    m_master_storage->hash_and_save_password(password);
    return true;
}


bool PasswordManagerApp::login(const secure_string& password)
{
    if(is_logged_in())
    {
        return true;
    }
    if(!m_master_storage->verify_password(password))
    {
        return false;
    }
    m_vault = std::make_unique<Vault>(
            std::move(m_vault_storage), std::move(m_crypto_engine), std::move(m_formatter), password);
    return true;
}


bool PasswordManagerApp::is_logged_in() const
{
    return m_vault != nullptr;
}


const secure_vector<Credentials>& PasswordManagerApp::get_credentials() const
{
   return m_vault->get_credentials();
}


void PasswordManagerApp::add_credentials(secure_string service, secure_string login, secure_string password)
{
    m_vault->add(Credentials(std::move(service), std::move(login), std::move(password)));
}


void PasswordManagerApp::remove_credentials(size_t index)
{
    m_vault->remove(index);
}


void PasswordManagerApp::change_security_level(const secure_string& master_password, SecurityLevel sec_level)
{
    if(!is_logged_in())
    {
        return;
    }
    if(!m_master_storage->verify_password(master_password))
    {
        return;
    }
    m_master_storage->change_security_level(sec_level);
    m_master_storage->hash_and_save_password(master_password);

    m_vault->change_key_derivation_security_level(master_password, sec_level);
}


void PasswordManagerApp::save()
{
    m_vault->save();
}


void PasswordManagerApp::logout()
{
    if(!is_logged_in()) return;

    save();
    m_vault.reset();
}