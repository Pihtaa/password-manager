cmake_minimum_required(VERSION 3.15)
project(PasswordManager VERSION 1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SOURCES
    src/main.cpp
    src/crypto.cpp
    src/password_gen.cpp
    src/master.cpp
    src/manager.cpp
    src/vault.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE include)

# libsodium
find_library(SODIUM_LIB sodium REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE ${SODIUM_LIB})

# json
find_package(nlohmann_json REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE nlohmann_json::nlohmann_json)

# threads
find_package(Threads REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE Threads::Threads)

# copy data
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/data DESTINATION ${CMAKE_CURRENT_BINARY_DIR})