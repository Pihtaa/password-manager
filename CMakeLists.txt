cmake_minimum_required(VERSION 3.15)
project(password_manager VERSION 1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_library(SODIUM_LIB sodium REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(Threads REQUIRED)

include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.2
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

set(SOURCES
    src/crypto.cpp
    src/password_gen.cpp
    src/master.cpp
    src/manager.cpp
    src/vault.cpp
)

add_library(${PROJECT_NAME}_lib STATIC ${SOURCES})

target_include_directories(${PROJECT_NAME}_lib PUBLIC include)

target_link_libraries(${PROJECT_NAME}_lib PUBLIC
    ${SODIUM_LIB}
    nlohmann_json::nlohmann_json
    Threads::Threads
)


add_executable(${PROJECT_NAME} src/main.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE ${PROJECT_NAME}_lib)


enable_testing()
add_subdirectory(tests)


file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/data DESTINATION ${CMAKE_CURRENT_BINARY_DIR})