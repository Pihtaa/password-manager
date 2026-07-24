#include <password_manager/master.h>
#include <gtest/gtest.h>
#include <string>

class MasterStorageTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        filename = next_path();
        storage.emplace(filename, crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN);
    }

    void TearDown() override
    {
        storage.reset();
        std::filesystem::remove(filename);
    }

    std::string filename;
    std::optional<MasterStorageBinFile> storage;

private:
    static std::string next_path()
    {
        static int n = 0;
        return "master_test_" + std::to_string(n++) + ".bin";
    }
};

TEST_F(MasterStorageTest, Works_SaveAndVerify)
{
    storage -> hash_and_save_password(secure_string("SuperSecretPasword1337"));
    EXPECT_TRUE(storage -> verify_password("SuperSecretPasword1337"));
}

TEST_F(MasterStorageTest, ReturnEmpty_WhenEmpty)
{
    EXPECT_FALSE(storage -> data_exists());
}

TEST_F(MasterStorageTest, ReturnNotEmpty_WhenNotEmpty)
{
    storage -> hash_and_save_password(secure_string("SuperSecretPasword1337"));
    EXPECT_TRUE(storage -> data_exists());
}

TEST_F(MasterStorageTest, ChangeSecurityLevel_WhenPasswordIsCorrect)
{
    storage -> hash_and_save_password(secure_string("SuperSecretPasword1337"));

    ASSERT_TRUE(storage -> change_security_level(secure_string("SuperSecretPasword1337"), SecurityLevel::Moderate));
    EXPECT_TRUE(storage -> verify_password(secure_string("SuperSecretPasword1337")));
}

TEST_F(MasterStorageTest, DontChangeSecurityLevel_WhenPasswordIsNotCorrect)
{
    storage -> hash_and_save_password(secure_string("SuperSecretPasword1337"));

    ASSERT_FALSE(storage -> change_security_level(secure_string("IncorrectPassword"), SecurityLevel::Moderate));
    EXPECT_TRUE(storage -> verify_password(secure_string("SuperSecretPasword1337")));
}

TEST_F(MasterStorageTest, DontInitializePassword_WhenWeak)
{
    EXPECT_FALSE(storage -> initialize_password_with_approvement(secure_string("weakpassword")));
    EXPECT_FALSE(storage -> data_exists());
    EXPECT_THROW(storage -> verify_password(secure_string("weakpassword")), std::logic_error);
}

TEST_F(MasterStorageTest, InitializePassword_WhenNotWeak)
{
    EXPECT_TRUE(storage -> initialize_password_with_approvement(secure_string("SoStrongPassword123")));
    EXPECT_TRUE(storage -> data_exists());

}