#include <gtest/gtest.h>
#include <sodium.h>

int main(int argc, char** argv)
{
    testing::InitGoogleTest(&argc, argv);
    if (sodium_init() < 0)
        return 1;
    return RUN_ALL_TESTS();
}