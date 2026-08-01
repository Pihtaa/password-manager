#include <password_manager/vault.h>
#include <gtest/gtest.h>
#include <password_manager/crypto.h>
#include <memory>

class VaultStorageJsonTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        filename = next_path();
        VaultStorageJson vsj(filename);
        storage = std::make_unique<VaultStorageJson>(vsj);
    }

    void TearDown() override
    {
        storage.reset();
        std::filesystem::remove(filename);
    }

    std::string filename;
    //std::optional<VaultStorageJson> storage;
    std::unique_ptr<IVaultStorage> storage;
private:
    static std::string next_path()
    {
        static int n = 0;
        return "master_test_" + std::to_string(n++) + ".bin";
    }
};

TEST_F(VaultStorageJsonTest, ReturnFalse_WhenEmpty)
{
    EXPECT_FALSE(storage -> vault_exists());
}

TEST_F(VaultStorageJsonTest, ReturnTheSame_AfterBinAndBase64Convertions)
{
    LibsodiumCryptoEngine lce;
    RawVaultData data;
    data.nonce = lce.generate_nonce();
    data.salt = lce.generate_salt();
    secure_vector<unsigned char> data_bin{'d','a','t','a',};

    storage->save_raw_data(data);
    RawVaultData data2 = storage->load_vault();

    EXPECT_EQ(data.nonce, data2.nonce);
    EXPECT_EQ(data.salt, data2.salt);
    EXPECT_EQ(data.ciphertext, data2.ciphertext);
}

TEST_F(VaultStorageJsonTest, VaultExists_ReturnTrue_WhenVaultExists)
{
    LibsodiumCryptoEngine lce;
    RawVaultData data;
    data.nonce = lce.generate_nonce();
    data.salt = lce.generate_salt();
    secure_vector<unsigned char> data_bin{'d','a','t','a',};

    storage->save_raw_data(data);

    EXPECT_TRUE(storage->vault_exists());
}
/*
TEST(JsonCredentialsFormatterTest, ReturnTheSame_AfterEncodeAndDecode)
{
    JsonCredentialsFormatter jcf;

}
    */