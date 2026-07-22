#pragma once

#include <string>
#include <vector>
#include <sodium.h>
#include <new> // std::bad_alloc
#include <cstddef> // std::size_t

template <typename T>
struct SodiumAllocator
{
    using value_type = T;

    using propagate_on_container_copy_assignment = std::true_type;
    using propagate_on_container_move_assignment = std::true_type;
    using propagate_on_container_swap            = std::true_type;

    template <typename U>
    struct rebind { using other = SodiumAllocator<U>; };


    T* allocate(std::size_t n)
    {
        void* ptr = sodium_allocarray(n, sizeof(T));
        if (!ptr) 
        {
            throw std::bad_alloc();
        }
        return static_cast<T*>(ptr);
    }


    void deallocate(T* ptr, std::size_t n) noexcept
    {
        sodium_free(ptr);
    }

    friend bool operator==(const SodiumAllocator&, const SodiumAllocator&) noexcept { return true; }
    friend bool operator!=(const SodiumAllocator&, const SodiumAllocator&) noexcept { return false; }
};


using secure_string = std::basic_string<char, std::char_traits<char>, SodiumAllocator<char>>;
template <typename T>
using secure_vector = std::vector<T, SodiumAllocator<T>>;