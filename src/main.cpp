#include "password_manager/manager.h"
#include <iostream>
#include <limits>

static void clear_input()
{
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

int main()
{
    if (sodium_init() < 0)
    {
        std::cerr << "Failed to initialize libsodium.\n";
        return 1;
    }

    auto master_storage  = std::make_unique<MasterStorageBinFile>("master.bin");
    auto checker         = std::make_unique<BasicPasswordStrengthChecker>();
    auto vault_storage   = std::make_unique<VaultStorageJson>("vault.json");
    auto crypto_engine   = std::make_unique<LibsodiumCryptoEngine>();
    auto formatter       = std::make_unique<JsonCredentialsFormatter>();
    auto pass_generator  = std::make_unique<SodiumPasswordGenerator>();

    PasswordManagerApp app(
        std::move(master_storage),
        std::move(checker),
        std::move(vault_storage),
        std::move(crypto_engine),
        std::move(formatter),
        std::move(pass_generator),
        "vault.json"
    );

    // --- First run? Setup master password ---
    if (app.is_first_run())
    {
        std::cout << "No master password found. Please set one.\n";
        secure_string pw;
        while (true)
        {
            std::cout << "Enter master password: ";
            std::getline(std::cin, pw);
            if (app.setup_master_password(pw))
                break;
            std::cout << "Too weak. " << BasicPasswordStrengthChecker().requirements_description() << "\n";
        }
        std::cout << "Master password set.\n\n";
    }

    // --- Login loop ---
    {
        secure_string pw;
        while (true)
        {
            std::cout << "Enter master password: ";
            std::getline(std::cin, pw);
            if (app.login(pw))
                break;
            std::cout << "Wrong password.\n";
        }
    }

    // --- Main menu ---
    bool running = true;
    while (running)
    {
        std::cout << "\n=== Password Manager ===\n"
                  << "1) Show all credentials\n"
                  << "2) Add credential\n"
                  << "3) Remove credential\n"
                  << "4) Change security level\n"
                  << "5) Change master password\n"
                  << "6) Exit\n"
                  << ">_ ";

        int choice;
        std::cin >> choice;
        clear_input();

        switch (choice)
        {
        case 1:
        {
            const auto& creds = app.get_credentials();
            if (creds.empty())
            {
                std::cout << "No credentials saved.\n";
            }
            else
            {
                for (size_t i = 0; i < creds.size(); ++i)
                {
                    std::cout << i << ") " << creds[i];
                }
            }
            break;
        }
        case 2:
        {
            std::string service, login, password;
            std::cout << "Service: ";  std::getline(std::cin, service);
            std::cout << "Login: ";    std::getline(std::cin, login);
            std::cout << "Password: "; std::getline(std::cin, password);
            app.add_credentials(
                secure_string(service.begin(), service.end()),
                secure_string(login.begin(), login.end()),
                secure_string(password.begin(), password.end())
            );
            std::cout << "Added.\n";
            break;
        }
        case 3:
        {
            std::cout << "Index to remove: ";
            size_t idx;
            std::cin >> idx;
            clear_input();
            try
            {
                app.remove_credentials(idx);
                std::cout << "Removed.\n";
            }
            catch (std::exception ex)
            {
                ex.what();
            }
            catch(...)
            {
                std::cout << "Unexpected error.";
            }
            break;
        }
        case 4:
        {
            std::cout << "Security level (0 = Low, 1 = Moderate, 2 = High): ";
            int level;
            std::cin >> level;
            clear_input();
            if (level < 0 || level > 2)
            {
                std::cout << "Invalid.\n";
                break;
            }
            secure_string master_pw;
            std::cout << "Confirm master password: ";
            std::getline(std::cin, master_pw);
            app.change_security_level(master_pw, static_cast<SecurityLevel>(level));
            std::cout << "Security level changed.\n";
            break;
        }
        case 5:
        {
            secure_string cur_master_password;
            std::cout << "Enter current master password: ";
            std::getline(std::cin, cur_master_password);
            if (!app.verify_master_password(cur_master_password)) {
                std::cout << "Wrong password.\n";
                break;
            }
            const auto& creds = app.get_credentials();
            secure_string new_password;
            std::cout << "Enter new password: ";
            std::getline(std::cin, new_password);
            if (!app.check_master_password_strength(new_password)) {
                std::cout << "New password is too weak.\n";
            } else {
                app.put_master_password(new_password);
                app.rederive_master_key(new_password);
                std::cout << "New password is set.\n";
            }
            
        }   
        case 6:
            app.save();
            app.logout();
            running = false;
            break;
        default:
            std::cout << "Invalid option.\n";
        }
    }

    std::cout << "Goodbye.\n";
    return 0;
}