#include "password_manager/manager.h"

int main()
{
    if(sodium_init() < 0)
    {
        return 1;
    }
}