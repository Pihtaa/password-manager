add_executable(test_password_gen test_password_gen.cpp)
target_link_libraries(test_password_gen PRIVATE
    password_manager_lib
    gtest_main
)
add_test(NAME test_password_gen COMMAND test_password_gen)

add_executable(test_crypto test_crypto.cpp)
target_link_libraries(test_crypto PRIVATE
    password_manager_lib
    gtest_main
)
add_test(NAME test_crypto COMMAND test_crypto)

add_executable(test_vault test_vault.cpp)
target_link_libraries(test_vault PRIVATE
    password_manager_lib
    gtest_main
)
add_test(NAME test_vault COMMAND test_vault)

add_executable(test_master test_master.cpp)
target_link_libraries(test_master PRIVATE
    password_manager_lib
    gtest_main
)
add_test(NAME test_master COMMAND test_master)