#pragma once

#include <stdexcept>


// custom exceptions
struct KeyDerivationError        : std::runtime_error { using std::runtime_error::runtime_error; };
struct EncryptionError           : std::runtime_error { using std::runtime_error::runtime_error; };
struct DecryptionError           : std::runtime_error { using std::runtime_error::runtime_error; };
struct PasswordGenerationError   : std::runtime_error { using std::runtime_error::runtime_error; };
struct SodiumInitError           : std::runtime_error { using std::runtime_error::runtime_error; };
struct VaultOpenFileError        : std::runtime_error { using std::runtime_error::runtime_error; };
struct VaultCheckPasswordError   : std::logic_error   { using std::logic_error::logic_error;     };
struct VaultPasswordHashingError : std::runtime_error { using std::runtime_error::runtime_error; };


