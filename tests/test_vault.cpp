#include <password_manager/vault.h>
#include <gtest/gtest.h>

class MasterStorageTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        filename = next_path();
        storage.emplace(VaultStorageJson(filename));
    }

    void TearDown() override
    {
        storage.reset();
        std::filesystem::remove(filename);
    }

    std::string filename;
    std::optional<VaultStorageJson> storage;

private:
    static std::string next_path()
    {
        static int n = 0;
        return "master_test_" + std::to_string(n++) + ".bin";
    }
};

TEST_F(MasterStorageTest, ReturnFalse_WhenEmpty)
{
    EXPECT_FALSE(storage -> vault_exists());
}
/*
TEST_F(MasterStorageTest, ShowTheSame_AfterManipulations)
{
    RawVaultData data;
    data.salt = 
}
*/