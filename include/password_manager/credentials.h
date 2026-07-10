#pragma once

#include <iostream>

class Credentials
{
protected:
    char service[64];
    char login[64];
    char password[64];

public:
    friend std::ostream& operator<<(std::ostream& os, const Credentials& cred);
};

