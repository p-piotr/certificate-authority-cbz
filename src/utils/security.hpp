#pragma once

#include <cstdint>
#include <concepts>
#include <span>
#include <iostream>
#include <vector>
#include <gmpxx.h>
#include "debug.h"

namespace CBZ::Security {

    // Securely zeroes memory 
    // Beware! this function does NOT free the memory after zeroing!
    //
    // Input:
    // @ptr - pointer to the memory which should be zeroed
    // @size - size of the memory region to zeroize, in bytes
    inline void secure_zero_memory(void* ptr, size_t size) {
        if (ptr != nullptr) {
            volatile uint8_t* vptr = reinterpret_cast<volatile uint8_t*>(ptr);
            for (size_t i = 0; i < size; i++)
                vptr[i] = 0;

            #ifdef SECURE_FREE_DEBUG
            std::cerr << "[secure_free] Cleared " << size << " bytes at " << reinterpret_cast<void*>(ptr) << std::endl;
            #endif // SECURE_FREE_DEBUG
        }
    }

    template <typename _T, size_t _Extent>
    inline void secure_zero_memory(std::span<_T, _Extent> s) {
        secure_zero_memory(s.data(), s.size_bytes());
    }

    // Concept for an object applicable to be securely deleted
    // it must be memory-contiguous
    template <typename _R>
    concept ContiguousRange = std::ranges::contiguous_range<_R>;

    // Securely zeroes memory of a given object
    // Beware! this function does NOT free the memory after zeroing!
    //
    // Input:
    // @sp - object to zeroize
    template <ContiguousRange _R>
    inline void secure_zero_memory(_R&& cr) {
        secure_zero_memory(std::span{cr});
    }

    // Securely zeroes and deletes the container
    // This function should be used as a custom deletor
    // when creating an object with a smart pointer
    //
    // Input:
    // @ptr - raw pointer to the container object
    template <ContiguousRange _R>
    inline void secure_delete(_R* ptr) {
        secure_zero_memory(*ptr);
        delete ptr;
    }

    // Securely zeores and deletes a structure
    //
    // Input:
    // @s - raw pointer to the structure
    template <typename _S>
    inline void secure_delete_struct(_S* s) {
        constexpr size_t size = sizeof(_S);
        secure_zero_memory(s, size);
        delete s;
    }

    // Securely zeroes and frees the memory
    //
    // Input:
    // @ptr - pointer to the memory
    // @size - size of the memory, in bytes
    inline void secure_free_memory(void* ptr, size_t size) {
        secure_zero_memory(ptr, size);
        free(ptr);
    }

    inline void* mem_alloc_debug(size_t s) {
        static size_t total_memory = 0;

        total_memory += s;
        std::cerr << "[mem_alloc_cbz] Total memory allocated so far: " << total_memory << " bytes" << std::endl;
        return malloc(s);
    }

    inline void* mem_realloc_debug(void* p, size_t o, size_t n) {
        std::cerr << "[mem_realloc_cbz] Reallocating " << o << " bytes to " << n << " under " << p << std::endl;
        return realloc(p, n);
    }

    // Initializes GMP to use secure memory deallocation
    inline void mpz_initialize_secure_free_policy() {
        // Set custom memory deallocation function for GMP to ensure sensitive data is cleared from memory
        mp_set_memory_functions(
            #ifndef GMP_DEBUG
            nullptr, 
            nullptr,
            #else
            mem_alloc_debug,
            mem_realloc_debug,
            #endif // GMP_DEBUG
            secure_free_memory
        );
    }

    // used to compare two values in constant time
    // @arg1 - first value to be compared
    // @arg2 - second value to be compared
    // return value: true if equal else false
    template <ContiguousRange _R>
    inline bool const_equal(_R const& arg1, _R const& arg2){
        const auto s_arg1 = std::span{arg1};
        const auto s_arg2 = std::span{arg2};
        uint8_t diff = 0;

        // if they're of different size we will return false
        // but only after doing the comparsion anyway
        size_t count = std::min(s_arg1.size(), s_arg2.size());

        // a xor a = 0
        // so if any of the elements are not equal then diff won't be zero
        for (size_t i = 0; i < count; ++i) {
            diff |= s_arg1[i] ^ s_arg2[i];
        }

        // if they are of different size return false
        if(s_arg1.size() != s_arg2.size()) { return false; }

        // if diff == 0 return true
        return diff == 0;
    }
}