#include"password_manager\vault.h"


std::ostream& operator<<(std::ostream& os, const Credentials& cred)
{
    os <<" Service:  "<< cred.service <<"\n" 
       <<" Login:    "<< cred.login <<"\n"
       <<" Password: "<< cred.password<<std::endl;
    return os;
}


secure_string VaultStorageJson::bin_to_base64(const void* data, size_t size) const
{
    secure_string string_to_return(sodium_base64_ENCODED_LEN(size, sodium_base64_VARIANT_ORIGINAL), '\0');
    sodium_bin2base64(string_to_return.data(), string_to_return.size(), reinterpret_cast<const unsigned char*>(data), size, static_cast<int>(sodium_base64_VARIANT_ORIGINAL));
    if (!string_to_return.empty() && string_to_return.back() == '\0')
    {
        string_to_return.pop_back();
    }
    return string_to_return;
}


secure_vector<unsigned char> VaultStorageJson::base64_to_bin(std::string& base64_str) const
{
    size_t max_len = base64_str.size();
    secure_vector<unsigned char> vector_to_return(max_len);
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
    sodium_memzero(base64_str.data(), base64_str.size());
    return vector_to_return;
}


void VaultStorageJson::save_raw_data(const RawVaultData& raw_vault_data)
{
    std::ofstream ofs(m_filename);
    if(ofs.fail())
    {
        throw VaultFileWriteError("Failed to open file to write json vault.");
    }

    json json_expr =
    {
        {"salt", bin_to_base64(raw_vault_data.salt.data(), raw_vault_data.salt.size())},
        {"nonce", bin_to_base64(raw_vault_data.nonce.data(), raw_vault_data.nonce.size())},
        {"ciphertext", bin_to_base64(raw_vault_data.ciphertext.data(), raw_vault_data.ciphertext.size())}
    };

    ofs << json_expr.dump(4); 
}

RawVaultData VaultStorageJson::load_vault() const
{

    std::ifstream ifs(m_filename);
    if(ifs.fail())
    {
        throw VaultFileReadError("Failed to open vault file to read data.");
    }
    if(!vault_exists())
    {
        throw VaultEmptyError("Empty vault.");
    }
    json json_expr = json::parse(ifs);

    RawVaultData data_to_return;
    data_to_return.salt       = Salt(base64_to_bin(json_expr["salt"].get_ref<std::string&>()));
    data_to_return.nonce      = Nonce(base64_to_bin(json_expr["nonce"].get_ref<std::string&>()));
    data_to_return.ciphertext = base64_to_bin(json_expr["ciphertext"].get_ref<std::string&>());   

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


secure_vector<Credentials> JsonCredentialsFormatter::decode(const secure_vector<unsigned char>& decrypted_data)
{
    secure_vector<Credentials> vec_to_return;
    json json_credentials = json::parse(decrypted_data.begin(), decrypted_data.end());
    for(auto& item : json_credentials)
    {
        auto& ref_s = item["service"].get_ref<std::string&>();
        auto& ref_l = item["login"].get_ref<std::string&>();
        auto& ref_p = item["password"].get_ref<std::string&>();
        vec_to_return.emplace_back(
            secure_string(ref_s.data(), ref_s.size()),
            secure_string(ref_l.data(), ref_l.size()),
            secure_string(ref_p.data(), ref_p.size())
        );
        sodium_memzero(ref_s.data(), ref_s.size());
        sodium_memzero(ref_l.data(), ref_l.size());
        sodium_memzero(ref_p.data(), ref_p.size());
    }

    return vec_to_return;
}

secure_vector<unsigned char> JsonCredentialsFormatter::encode(const secure_vector<Credentials>& cred_vector_for_formatting)
{
    json new_json_array = json::array();
    for(const auto& item : cred_vector_for_formatting)
    {
        new_json_array.push_back({
            {"service", item.service.data()},
            {"login", item.login.data()},
            {"password", item.password.data()}
        });
    }
    std::string json_str = new_json_array.dump(4);
    secure_vector<unsigned char> vector_to_return(json_str.begin(), json_str.end());
    sodium_memzero(json_str.data(), json_str.size());
    json_str.clear();
    for(auto& item : new_json_array)
    {
        auto& ref_s = item["service"].get_ref<std::string&>();
        auto& ref_l = item["login"].get_ref<std::string&>();
        auto& ref_p = item["password"].get_ref<std::string&>();
        sodium_memzero(ref_s.data(), ref_s.size());
        sodium_memzero(ref_l.data(), ref_l.size());
        sodium_memzero(ref_p.data(), ref_p.size());
        ref_s.clear();
        ref_l.clear();
        ref_p.clear();
    }
    return vector_to_return;
}


Vault::Vault(std::unique_ptr<IVaultStorage> storage, std::unique_ptr<ICryptoEngine> crypto_engine, 
    std::unique_ptr<ICredentialsFormatter> cred_formatter, const secure_string& password)
    : m_storage(std::move(storage)), m_crypto_engine(std::move(crypto_engine)), m_formatter(std::move(cred_formatter))
{
    RawVaultData raw_vault_data;
    if(!storage -> vault_exists())
    {
        raw_vault_data.salt = m_crypto_engine -> generate_salt();
        m_salt = raw_vault_data.salt;
        raw_vault_data.nonce = m_crypto_engine -> generate_nonce();

        m_session_key = m_crypto_engine -> derive_key(password, raw_vault_data.salt);

        json json_empty_credentials = json::array();

        std::string json_str = json_empty_credentials.dump(4);
        secure_vector<unsigned char> empty_plaintext(json_str.begin(), json_str.end());
        sodium_memzero(json_str.data(), json_str.size());
        json_str.clear();

        raw_vault_data.ciphertext = m_crypto_engine -> encrypt(empty_plaintext, m_session_key, raw_vault_data.nonce);
        m_storage -> save_raw_data(raw_vault_data);
    }
    else
    {
        raw_vault_data = m_storage -> load_vault();
        m_session_key = m_crypto_engine -> derive_key(password, raw_vault_data.salt);
        m_salt = raw_vault_data.salt;

        secure_vector<unsigned char> decrypted_bin_credentials = m_crypto_engine -> decrypt(raw_vault_data.ciphertext, m_session_key, raw_vault_data.nonce);
        m_credentials = m_formatter -> decode(decrypted_bin_credentials);

    }
}

void Vault::add(Credentials&& new_credentials)
{
    m_credentials.push_back(std::move(new_credentials));
    m_is_changed = true;
}


void Vault::remove(size_t pos)
{
    if(pos < m_credentials.size())
    {
        m_credentials.erase(m_credentials.begin() + pos);
        m_is_changed = true;
    }
    else
    {
        throw VaultRangeError("Pos fo erase in vault is out of range.");
    }
}


void Vault::save()
{
    if(!m_is_changed)
    {
        return;
    }
    RawVaultData new_data;

    new_data.nonce = m_crypto_engine -> generate_nonce();
    new_data.salt = m_salt;
    new_data.ciphertext = m_crypto_engine -> encrypt(m_formatter -> encode(m_credentials), m_session_key, new_data.nonce);

    m_storage -> save_raw_data(new_data);
    m_is_changed = false;
}




