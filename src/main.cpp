#include "password_manager/password_manager.h"

int main()
{
    if(sodium_init() < 0)
    {
        return 1;
    }
}