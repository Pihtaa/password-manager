#pragma once

#include <stdexcept>


// custom exceptions
struct KeyDerivationError          : std::runtime_error { using std::runtime_error::runtime_error; };
struct EncryptionError             : std::runtime_error { using std::runtime_error::runtime_error; };
struct DecryptionError             : std::runtime_error { using std::runtime_error::runtime_error; };
struct PasswordGenerationError     : std::runtime_error { using std::runtime_error::runtime_error; };
struct SodiumInitError             : std::runtime_error { using std::runtime_error::runtime_error; };
struct StorageOpenFileError        : std::runtime_error { using std::runtime_error::runtime_error; };
struct StorageCheckPasswordError   : std::logic_error   { using std::logic_error::logic_error;     };
struct StoragePasswordHashingError : std::runtime_error { using std::runtime_error::runtime_error; };
struct VaultFileWriteError         : std::runtime_error { using std::runtime_error::runtime_error; };
struct VaultFileReadError          : std::runtime_error { using std::runtime_error::runtime_error; };
struct VaultEmptyError             : std::runtime_error { using std::runtime_error::runtime_error; };
struct VaultError                  : std::runtime_error { using std::runtime_error::runtime_error; };
struct LibsodiunInitError          : std::runtime_error { using std::runtime_error::runtime_error; };
struct VaultRangeError             : std::runtime_error { using std::runtime_error::runtime_error; };
struct SecureDataVecSizeError      : std::runtime_error { using std::runtime_error::runtime_error; };
