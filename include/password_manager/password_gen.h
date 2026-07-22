#pragma once

#include <cstdint>
#include "password_manager\exceptions.h"
#include <sodium.h>

struct PasswordParameters
{
    size_t length = 20;

    bool use_lowercase = true;
    bool use_uppercase = true;
    bool use_digits    = true;
    bool use_special   = true;

    void validate() const;
    size_t min_length() const noexcept;

};



std::string generate_password(const PasswordParameters& parameters);
