#include"password_manager\vault.h"

#include<iostream>


std::ostream& operator<<(std::ostream& os, const Credentials& cred)
{
    os <<" Service:  "<< cred.service <<"\n" 
       <<" Login:    "<< cred.login <<"\n"
       <<" Password: "<< cred.password<<std::endl;
    return os;
}


std::string VaultStorageJson::bin_to_base64(const void* data, size_t size)
{
    std::string string_to_return(sodium_base64_ENCODED_LEN(size, sodium_base64_VARIANT_ORIGINAL), '\0');
    sodium_bin2base64(string_to_return.data(), string_to_return.size(), reinterpret_cast<const unsigned char*>(data), size, sodium_base64_VARIANT_ORIGINAL);
    if (!string_to_return.empty() && string_to_return.back() == '\0')
    {
        string_to_return.pop_back();
    }
    return string_to_return;
}


std::vector<unsigned char> VaultStorageJson::base64_to_bin(std::string base64_str)
{
    size_t max_len = base64_str.size();
    std::vector<unsigned char> vector_to_return(max_len);
    
    size_t actual_len = 0;
    
    if(sodium_base642bin(
        vector_to_return.data(),
        max_len,
        base64_str.data(),
        base64_str.size(),
        nullptr,
        &actual_len,
        nullptr,
        sodium_base64_VARIANT_ORIGINAL
    ) != 0)
    {
        throw VaultError("Failed to convert base64 to bin.");
    }

    vector_to_return.resize(actual_len);

    return vector_to_return;
}


void VaultStorageJson::save_vault(const RawVaultData& raw_vault_data)
{
    std::ofstream ofs(m_filename);
    if(ofs.fail())
    {
        throw VaultFileWriteError("Failed to open file to write json vault.");
    }

    json json_expr =
    {
        {"salt", bin_to_base64(reinterpret_cast<const void*>(raw_vault_data.salt.data()), raw_vault_data.salt.size())},
        {"nonce", bin_to_base64(reinterpret_cast<const void*>(raw_vault_data.nonce.data()), raw_vault_data.nonce.size())},
        {"ciphertext", bin_to_base64(reinterpret_cast<const void*>(raw_vault_data.ciphertext.data()), raw_vault_data.ciphertext.size())}
    };

    ofs << json_expr.dump(4); 
}

RawVaultData VaultStorageJson::load_vault()
{
    std::ifstream ifs(m_filename);
    if(ifs.fail())
    {
        throw VaultFileReadError("Failed to open vault file to read data.");
    }
    json json_expr = json::parse(ifs);

    RawVaultData data_to_return;
    data_to_return.salt       = base64_to_bin(json_expr["salt"].get<std::string>());
    data_to_return.nonce      = base64_to_bin(json_expr["nonce"].get<std::string>());
    data_to_return.ciphertext = base64_to_bin(json_expr["ciphertext"].get<std::string>());
    
    return data_to_return;
}


bool VaultStorageJson::vault_exists() const
{
    std::filesystem::path path = m_filename;
    if(std::filesystem::exists(path) && !std::filesystem::is_empty(path))
    {
        return true;
    }
    return false;
}


