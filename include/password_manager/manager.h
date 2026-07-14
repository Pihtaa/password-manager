#pragma once

#include "password_gen.h"

#include <stdexcept>
#include <iostream> 
#include <stdint.h>
#include <string> // for strings in programm processes
#include <cstring> // bytes operations (memcopy /  )
#include <sodium.h>
#include <vector>
#include <array>



class Credentials
{
protected:
    char service[64];
    char login[64];
    char password[64];

public:
    friend std::ostream& operator<<(std::ostream& os, const Credentials& cred);
};