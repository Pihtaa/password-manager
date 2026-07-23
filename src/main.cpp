#include "password_manager/manager.h"

int main()
{
    if(sodium_init() < 0)
    {
        return 1;
    }
    PasswordParameters param;
    auto str1 = generate_password(param);
    auto str2 = generate_password(param);
    std::cout << str1 << std::endl << str2;
}