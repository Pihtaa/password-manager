#include"password_manager\vault.h"

void VaultBinFile::save_data(const VaultData& vault_data)
{
    std::ofstream ofs(filename, std::ios::binary | std::ios::trunc);
    if(ofs.fail())
    {
        throw VaultOpenFileError("Failed to open file to save master password and salt.");
    }
    ofs.write(reinterpret_cast<const char*>(&vault_data), sizeof(VaultData));
}

void VaultBinFile::set_opslimit(unsigned long long opslimit)
{
    OPSLIMIT = opslimit;
}

void VaultBinFile::set_memlimit(unsigned long long memlimit)
{
    MEMLIMIT = memlimit;
}


VaultData VaultBinFile::load_data()
{
    std::ifstream ifs(filename, std::ios::binary);
    if(ifs.fail())
    {
        throw VaultOpenFileError("Failed to open file to read neccesary master password data.");
    }
    VaultData data_from_file;
    ifs.read(reinterpret_cast<char*>(&data_from_file), sizeof(VaultData));
    return data_from_file;
}

bool VaultBinFile::data_exists() const      
{
    std::filesystem::path path = filename;
    if(std::filesystem::exists(path) && !std::filesystem::is_empty(path))
    {
        return true;
    }
    return false;
}

bool VaultBinFile::verify_password(const std::string& password)
{
    if(!data_exists())
    {
        throw VaultCheckPasswordError("Error: file is empty, can not veerify password.");
    }
    VaultData cur_data = load_data();

    if(crypto_pwhash_str_verify(cur_data.hashed_password_str.data(), password.c_str(), password.length()) == 0)
    {
        return true;
    }
    else
    {
        return false;
    }
}

void VaultBinFile::hash_and_save_password(const std::string& password)
{
    if(password.length() < crypto_pwhash_PASSWD_MIN)
    {
        throw VaultCheckPasswordError("Password is too small.");
    }
    if(password.length() > crypto_pwhash_PASSWD_MAX)
    {
        throw VaultCheckPasswordError("Password is too big.");
    }

    VaultData data_to_save;
    if(crypto_pwhash_str(data_to_save.hashed_password_str.data(), password.c_str(), password.length(), OPSLIMIT, MEMLIMIT) != 0)
    {
        throw VaultCheckPasswordError("Failed to hash password. Probably memory limit is too big.");
    }
    save_data(data_to_save);
}