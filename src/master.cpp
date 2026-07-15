#include"password_manager\master.h"

void MasterStorageBinFile::save_data(const MasterPasswordData& master_password_data)
{
    std::ofstream ofs(filename, std::ios::binary | std::ios::trunc);
    if(ofs.fail())
    {
        throw VaultOpenFileError("Failed to open file to save master password and salt.");
    }
    ofs.write(reinterpret_cast<const char*>(&master_password_data), sizeof(MasterPasswordData));
}

void MasterStorageBinFile::set_opslimit(unsigned long long opslimit)
{
    OPSLIMIT = opslimit;
}

void MasterStorageBinFile::set_memlimit(unsigned long long memlimit)
{
    MEMLIMIT = memlimit;
}


MasterPasswordData MasterStorageBinFile::load_data() const
{
    std::ifstream ifs(filename, std::ios::binary);
    if(ifs.fail())
    {
        throw VaultOpenFileError("Failed to open file to read neccesary master password data.");
    }
    MasterPasswordData data_from_file;
    ifs.read(reinterpret_cast<char*>(&data_from_file), sizeof(MasterPasswordData));
    return data_from_file;
}

bool MasterStorageBinFile::data_exists() const      
{
    std::filesystem::path path = filename;
    if(std::filesystem::exists(path) && !std::filesystem::is_empty(path))
    {
        return true;
    }
    return false;
}

bool MasterStorageBinFile::verify_password(const std::string& password) const
{
    if(!data_exists())
    {
        throw VaultCheckPasswordError("Error: file is empty, can not veerify password.");
    }
    MasterPasswordData cur_data = load_data();

    if(crypto_pwhash_str_verify(cur_data.hashed_password_str.data(), password.c_str(), password.length()) == 0)
    {
        return true;
    }
    else
    {
        return false;
    }
}

void MasterStorageBinFile::hash_and_save_password(const std::string& password)
{
    if(password.length() < crypto_pwhash_PASSWD_MIN)
    {
        throw VaultCheckPasswordError("Password is too small.");
    }
    if(password.length() > crypto_pwhash_PASSWD_MAX)
    {
        throw VaultCheckPasswordError("Password is too big.");
    }

    MasterPasswordData data_to_save;
    if(crypto_pwhash_str(data_to_save.hashed_password_str.data(), password.c_str(), password.length(), OPSLIMIT, MEMLIMIT) != 0)
    {
        throw VaultCheckPasswordError("Failed to hash password. Probably memory limit is too big.");
    }
    save_data(data_to_save);
}

bool MasterStorageBinFile::is_strong_password(const std::string& password)
{
    if (password.length() < min_required_length) return false;
    
    bool has_lower   = false;
    bool has_upper   = false;
    bool has_digit   = false;
    bool has_special = false;

    for (char c : password)
    {
        if (std::islower(c)) has_lower = true;
        if (std::isupper(c)) has_upper = true;
        if (std::isdigit(c)) has_digit = true;
        if (std::ispunct(c)) has_special = true;
    }

    return has_lower && has_upper && has_digit && has_special;
}

bool MasterStorageBinFile::change_security_level(const std::string& password, SecurityLevel sec_level)
{
    if(verify_password(password))
    {
        switch(sec_level)
        {
        case SecurityLevel::Low:
            set_opslimit(crypto_pwhash_OPSLIMIT_MIN);
            set_memlimit(crypto_pwhash_MEMLIMIT_MIN);
            break;
        case SecurityLevel::Moderate:
            set_opslimit(crypto_pwhash_OPSLIMIT_MODERATE);
            set_memlimit(crypto_pwhash_MEMLIMIT_MODERATE);
            break;
        case SecurityLevel::High:
            set_opslimit(crypto_pwhash_OPSLIMIT_SENSITIVE);
            set_memlimit(crypto_pwhash_MEMLIMIT_SENSITIVE);
            break;
        }
        hash_and_save_password(password);
        return true;
    }
    return false;
}


bool MasterStorageBinFile::initialize_password_with_approvement(const std::string& password)
{
    if(!is_strong_password(password))
    {
        return false;
    }
    hash_and_save_password(password);
    return true;
}