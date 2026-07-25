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

TEST_F(MasterStorageTest, OverwritePassword_StillVerifiesNew)
{
    storage->initialize_password_with_approvement("FirstP@ss1");
    storage->initialize_password_with_approvement("SecondP@ss12");
    EXPECT_TRUE(storage->verify_password("SecondP@ss12"));
    EXPECT_FALSE(storage->verify_password("FirstP@ss1"));
}

TEST_F(MasterStorageTest, ChangeSecurityLevel_AllLevels)
{
    storage->initialize_password_with_approvement("StrongP@ss12");
    for (auto level : {SecurityLevel::Low, SecurityLevel::Moderate, SecurityLevel::High})
    {
        ASSERT_TRUE(storage->change_security_level("StrongP@ss12", level));
        EXPECT_TRUE(storage->verify_password("StrongP@ss12"));
    }
}

TEST_F(MasterStorageTest, InitializePassword_When12Chars)
{
    EXPECT_TRUE(storage->initialize_password_with_approvement("Abcd1234!@#x"));  // 12
}

TEST_F(MasterStorageTest, DontInitializePassword_When11Chars)
{
    EXPECT_FALSE(storage->initialize_password_with_approvement("Abcd1234!@#"));   // 11
}

TEST_F(MasterStorageTest, DontInitializePassword_WhenNoLowercase)
{
    EXPECT_FALSE(storage->initialize_password_with_approvement("ABCD1234!@#$"));
}

TEST_F(MasterStorageTest, DontInitializePassword_WhenNoUppercase)
{
    EXPECT_FALSE(storage->initialize_password_with_approvement("abcd1234!@#$"));
}

TEST_F(MasterStorageTest, DontInitializePassword_WhenNoDigit)
{
    EXPECT_FALSE(storage->initialize_password_with_approvement("Abcdefgh!@#$"));
}

TEST_F(MasterStorageTest, Sequence_Strong_Weak_Strong)
{
    EXPECT_TRUE(storage->initialize_password_with_approvement("FirstP@ss1234"));
    EXPECT_FALSE(storage->initialize_password_with_approvement("weak"));
    EXPECT_TRUE(storage->initialize_password_with_approvement("OtherP@ss223"));
    EXPECT_TRUE(storage->verify_password("OtherP@ss223"));
}