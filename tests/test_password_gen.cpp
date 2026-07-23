#include <password_manager/password_gen.h>
#include <gtest/gtest.h>
#include <cctype>

TEST(PasswordGenTest, Works_WhenDefaultParams)
{
    // arrange
    PasswordParameters params;

    // act
    auto pwd = generate_password(params);

    // assert
    EXPECT_EQ(pwd.length(), params.length);
    EXPECT_FALSE(pwd.empty());
}

TEST(PasswordGenTest, Throws_WhenAllSymbolsFalse)
{
    // arrange
    PasswordParameters params;

    // act
    params.use_digits = params.use_lowercase = 
    params.use_special = params.use_uppercase = false;

    // assert
    EXPECT_THROW(params.validate(), std::invalid_argument);
}

TEST(PasswordGenTest, Throws_WhenLengthLessThanMinLength)
{
    // arrange
    PasswordParameters params;

    // act 
    params.length = 0;

    // assert
    EXPECT_THROW(auto pwd = generate_password(params), std::invalid_argument);
}

TEST(PasswordGenTest, ReturnDifferentPasswords)
{
    // arrange
    PasswordParameters params;

    // act
    auto psw1 = generate_password(params);
    auto psw2 = generate_password(params);

    // assert
    EXPECT_NE(psw1, psw2);
}

TEST(PasswordGenTest, Works_WithBasicParam)
{
    // arrange
    PasswordParameters params;

    // act & assert
    EXPECT_NO_THROW(params.validate());
    EXPECT_TRUE(params.min_length() == 4);
}

TEST(PasswordGenTest, Match_WhenSymbolsConfigTTTT)
{
    //arrange
    PasswordParameters paramsTTTT;
    bool low, up, dig, spec;
    low = up = dig = spec = false;

    //act
    auto psw = generate_password(paramsTTTT);
    for(char symbol : psw)
    {
        if(std::islower(symbol)) low = true;
        else if(std::isupper(symbol)) up = true;
        else if(std::isdigit(symbol)) dig = true;
        else if(std::ispunct(symbol)) spec = true;
    }

    //assert
    EXPECT_TRUE(low && up && dig && spec);
}

TEST(PasswordGenTest, Match_SymbolsConfigTTTF)
{
    //arrange
    PasswordParameters paramsTTTF;
    paramsTTTF.use_special = false;
    bool low, up, dig, spec;
    low = up = dig = spec = false;

    //act
    auto psw = generate_password(paramsTTTF);
    for(char symbol : psw)
    {
        if(std::islower(symbol)) low = true;
        else if(std::isupper(symbol)) up = true;
        else if(std::isdigit(symbol)) dig = true;
        else if(std::ispunct(symbol)) spec = true;
    }

    //assert
    EXPECT_TRUE(low && up && dig && !spec);
}

TEST(PasswordGenTest, Match_SymbolsConfigTFFF)
{
    //arrange
    PasswordParameters paramsTTTF;
    paramsTTTF.use_special = paramsTTTF.use_digits 
    = paramsTTTF.use_uppercase = false;
    bool low, up, dig, spec;
    low = up = dig = spec = false;

    //act
    auto psw = generate_password(paramsTTTF);
    for(char symbol : psw)
    {
        if(std::islower(symbol)) low = true;
        else if(std::isupper(symbol)) up = true;
        else if(std::isdigit(symbol)) dig = true;
        else if(std::ispunct(symbol)) spec = true;
    }

    //assert
    EXPECT_TRUE(low && !up && !dig && !spec);
}

TEST(PasswordGenTest, Match_SymbolsConfigFTFF)
{
    //arrange
    PasswordParameters paramsTTTF;
    paramsTTTF.use_special = paramsTTTF.use_digits 
    = paramsTTTF.use_lowercase = false;
    bool low, up, dig, spec;
    low = up = dig = spec = false;

    //act
    auto psw = generate_password(paramsTTTF);
    for(char symbol : psw)
    {
        if(std::islower(symbol)) low = true;
        else if(std::isupper(symbol)) up = true;
        else if(std::isdigit(symbol)) dig = true;
        else if(std::ispunct(symbol)) spec = true;
    }

    //assert
    EXPECT_TRUE(!low && up && !dig && !spec);
}

TEST(PasswordGenTest, MinLength_ReturnsCorrectCount)
{
    PasswordParameters p{};
    EXPECT_EQ(p.min_length(), 4);

    p.use_digits = false;
    EXPECT_EQ(p.min_length(), 3);

    p.use_lowercase = p.use_uppercase = p.use_special = false;
    EXPECT_EQ(p.min_length(), 0);
}

