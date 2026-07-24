#pragma once

#include <cstdint>
#include "password_manager\exceptions.h"
#include "password_manager\crypto.h"
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

class IPasswordGenerator
{
public:
    virtual secure_string generate_password(const PasswordParameters& parameters) = 0;

    virtual ~IPasswordGenerator() = default;
};

class SodiumPasswordGenerator : public IPasswordGenerator
{
public:
    secure_string generate_password(const PasswordParameters& parameters);

};

//secure_string generate_password(const PasswordParameters& parameters);
