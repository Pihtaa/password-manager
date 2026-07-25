#include <password_manager/crypto.h>
#include <gtest/gtest.h>

class CryptoEngineTest : public ::testing::Test
{
protected:
    std::unique_ptr<ICryptoEngine> cr_en;

    void SetUp() override
    {
        cr_en = std::make_unique<LibsodiumCryptoEngine>();
    }
};

TEST_F(CryptoEngineTest, SaltsDifferent_WhenGenerate)
{
    auto salt1 = cr_en->generate_salt();
    auto salt2 = cr_en->generate_salt();

    EXPECT_NE(salt1, salt2);
}

TEST_F(CryptoEngineTest, NoncesDifferent_WhenGenerate)
{
    auto nonce1 = cr_en->generate_nonce();
    auto nonce2 = cr_en->generate_nonce();

    EXPECT_NE(nonce1, nonce2);
}

TEST_F(CryptoEngineTest, GenerateSameKey_WhenSameSaltAndPassword)
{
    secure_string password("SuperPassword123");
    auto salt = cr_en->generate_salt();

    auto key1 = cr_en->derive_key(password, salt);
    auto key2 = cr_en->derive_key(password, salt);

    EXPECT_EQ(key1, key2);
}

TEST_F(CryptoEngineTest, GenerateDifferentKey_WhenDifferentSaltsAndSamePassword)
{
    secure_string password("SuperPassword123");
    auto salt1 = cr_en->generate_salt();
    auto salt2 = cr_en->generate_salt();

    auto key1 = cr_en->derive_key(password, salt1);
    auto key2 = cr_en->derive_key(password, salt2);

    EXPECT_NE(key1, key2);
}

TEST_F(CryptoEngineTest, GenerateDifferentKey_WhenDifferentSaltsAndDifferentPasswords)
{
    secure_string password1("SuperPassword123");
    secure_string password2("VerySuperPassword123");
    auto salt1 = cr_en->generate_salt();
    auto salt2 = cr_en->generate_salt();

    auto key1 = cr_en->derive_key(password1, salt1);
    auto key2 = cr_en->derive_key(password2, salt2);

    EXPECT_NE(key1, key2);
}

TEST_F(CryptoEngineTest, GenerateDifferentKey_WhenSameSaltAndDifferentPasswords)
{
    secure_string password1("SuperPassword123");
    secure_string password2("VerySuperPassword123");
    auto salt = cr_en->generate_salt();

    auto key1 = cr_en->derive_key(password1, salt);
    auto key2 = cr_en->derive_key(password2, salt);

    EXPECT_NE(key1, key2);
}

TEST_F(CryptoEngineTest, CiphertextDiffersFromPlaintext_WhenEncrypt)
{
    secure_string password("SuperPassword123");
    Salt salt = cr_en->generate_salt();
    Key key = cr_en->derive_key(password, salt);
    Nonce nonce = cr_en->generate_nonce();
    secure_vector<unsigned char> plaintext{'p','l','a','i','n'};

    secure_vector<unsigned char> ciphertext = cr_en->encrypt(plaintext, key, nonce);

    EXPECT_NE(plaintext, ciphertext);
}

TEST_F(CryptoEngineTest, GeneratesDifferentCiphertext_WhenDifferentSalt)
{
    secure_string password("SuperPassword123");
    Salt salt1 = cr_en->generate_salt();
    Salt salt2 = cr_en->generate_salt();
    Key key1 = cr_en->derive_key(password, salt1);
    Key key2 = cr_en->derive_key(password, salt2);
    Nonce nonce = cr_en->generate_nonce();
    secure_vector<unsigned char> plaintext{'p','l','a','i','n'};

    secure_vector<unsigned char> ciphertext1 = cr_en->encrypt(plaintext, key1, nonce);
    secure_vector<unsigned char> ciphertext2 = cr_en->encrypt(plaintext, key2, nonce);

    EXPECT_NE(ciphertext1, ciphertext2);
}

TEST_F(CryptoEngineTest, GeneratesDifferentCiphertext_WhenDifferentNonce)
{
    secure_string password("SuperPassword123");
    Salt salt = cr_en->generate_salt();
    Key key = cr_en->derive_key(password, salt);
    Nonce nonce1 = cr_en->generate_nonce();
    Nonce nonce2 = cr_en->generate_nonce();
    secure_vector<unsigned char> plaintext{'p','l','a','i','n'};

    secure_vector<unsigned char> ciphertext1 = cr_en->encrypt(plaintext, key, nonce1);
    secure_vector<unsigned char> ciphertext2 = cr_en->encrypt(plaintext, key, nonce2);

    EXPECT_NE(ciphertext1, ciphertext2);
}

TEST_F(CryptoEngineTest, GivesSameData_AfterEncryptionAndDecryption)
{
    secure_string password("SuperPassword123");
    Salt salt = cr_en->generate_salt();
    Key key = cr_en->derive_key(password, salt);
    Nonce nonce = cr_en->generate_nonce();
    secure_vector<unsigned char> plaintext{'p','l','a','i','n'};

    secure_vector<unsigned char> ciphertext = cr_en->encrypt(plaintext, key, nonce);
    secure_vector<unsigned char> plaintext2 = cr_en->decrypt(ciphertext, key, nonce);

    EXPECT_EQ(plaintext, plaintext2);
}

TEST_F(CryptoEngineTest, Decrypt_Throws_WhenWrongKey)
{
    secure_string pwd1("Password123");
    secure_string pwd2("WrongPassword123");
    Salt salt = cr_en->generate_salt();
    Key key1 = cr_en->derive_key(pwd1, salt);
    Key key2 = cr_en->derive_key(pwd2, salt);
    Nonce nonce = cr_en->generate_nonce();

    secure_vector<unsigned char> plaintext{'p','l','a','i','n'};
    auto ciphertext = cr_en->encrypt(plaintext, key1, nonce);

    EXPECT_THROW(cr_en->decrypt(ciphertext, key2, nonce), DecryptionError);
}

TEST_F(CryptoEngineTest, Decrypt_Throws_WhenWrongNonce)
{
    secure_string pwd("Password123");
    Salt salt = cr_en->generate_salt();
    Key key = cr_en->derive_key(pwd, salt);
    Nonce nonce1 = cr_en->generate_nonce();
    Nonce nonce2 = cr_en->generate_nonce();

    secure_vector<unsigned char> plaintext{'p','l','a','i','n'};
    auto ciphertext = cr_en->encrypt(plaintext, key, nonce1);

    EXPECT_THROW(cr_en->decrypt(ciphertext, key, nonce2), DecryptionError);
}

TEST_F(CryptoEngineTest, Decrypt_Throws_WhenCiphertextCorrupted)
{
    secure_string pwd("Password123");
    Salt salt = cr_en->generate_salt();
    Key key = cr_en->derive_key(pwd, salt);
    Nonce nonce = cr_en->generate_nonce();

    secure_vector<unsigned char> plaintext{'p','l','a','i','n'};
    auto ciphertext = cr_en->encrypt(plaintext, key, nonce);

    ciphertext[0] ^= 0xFF;

    EXPECT_THROW(cr_en->decrypt(ciphertext, key, nonce), DecryptionError);
}

TEST_F(CryptoEngineTest, EncryptDecrypt_Works_WhenEmptyPlaintext)
{
    secure_string pwd("Password123");
    Salt salt = cr_en->generate_salt();
    Key key = cr_en->derive_key(pwd, salt);
    Nonce nonce = cr_en->generate_nonce();

    secure_vector<unsigned char> empty_plaintext{};
    auto ciphertext = cr_en->encrypt(empty_plaintext, key, nonce);
    auto decrypted = cr_en->decrypt(ciphertext, key, nonce);

    EXPECT_EQ(empty_plaintext, decrypted);
}
