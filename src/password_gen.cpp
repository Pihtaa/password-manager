#include "password_manager\password_gen.h"


void PasswordParameters::validate() const
{
    size_t min_len = static_cast<size_t>(use_lowercase) + static_cast<size_t>(use_uppercase) +
                        static_cast<size_t>(use_digits)    + static_cast<size_t>(use_special);
    if (min_len == 0)
    {
        throw std::invalid_argument("No symbol types selected.");
    }
    if (length < min_len)
    {
        throw std::invalid_argument("Length too short for selected groups.");
    }
    if (length > 64)
    {
        throw std::invalid_argument("Length too long.");
    }            
}

size_t PasswordParameters::min_length() const noexcept
{
    return static_cast<size_t>(use_lowercase) +
           static_cast<size_t>(use_uppercase) +
           static_cast<size_t>(use_digits)    +
           static_cast<size_t>(use_special);
}


std::string generate_password(const PasswordParameters& parameters)
{
    parameters.validate();
    const size_t min_len = parameters.min_length();

    static constexpr std::string_view lowercase = "abcdefghijklmnopqrstuvwxyz";
    static constexpr std::string_view uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static constexpr std::string_view digits    = "0123456789";
    static constexpr std::string_view special   = "!@#$%^&*()-_=+[]{}|;:,.<>?";

    std::string password;
    password.reserve(parameters.length);
    std::string pool;
    pool.reserve(lowercase.length() + uppercase.length() + digits.length() + special.length());

    if(parameters.use_lowercase)
    {
        pool += lowercase;
        password += lowercase[randombytes_uniform(static_cast<uint32_t>(lowercase.length()))];
    }
    if(parameters.use_uppercase)
    {
        pool += uppercase;
        password += uppercase[randombytes_uniform(static_cast<uint32_t>(uppercase.length()))];
    }
    if(parameters.use_digits)
    {
        pool += digits;
        password += digits[randombytes_uniform(static_cast<uint32_t>(digits.length()))];
    }
    if(parameters.use_special)
    {
        pool += special;
        password += special[randombytes_uniform(static_cast<uint32_t>(special.length()))];
    }
    

    for(size_t i = min_len; i < parameters.length; ++i)
    {
        uint32_t pool_len = static_cast<uint32_t>(pool.length());
        password.push_back(pool[randombytes_uniform(pool_len)]);
    }
    
    for(uint32_t i = static_cast<uint32_t>(parameters.length - 1); i > 0; --i)
    {
        std::swap(password[i], password[randombytes_uniform(i + 1)]);
    }

    return password;
}