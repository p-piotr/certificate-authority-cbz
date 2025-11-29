#pragma once

#include <cstdint>
#include <concepts>
#include <span>
#include <iostream>
#include <gmpxx.h>
#include <termios.h>
#include <unistd.h>
#include "debug.h"

namespace CBZ {

    /*
    I only marked those functions as inline because
    the compiler complained about multiple definitions during linking
    and I really didn't give a damn to create a separate .cpp file for them
    */

    // Enables (or disables) stdin echo
    // Temporarily disable while prompting for a passphrase or other secrets
    inline void set_stdin_echo(bool enable = true) {
        struct termios tty;
        tcgetattr(STDIN_FILENO, &tty);

        if (!enable)
            tty.c_lflag &= ~ECHO;
        else
            tty.c_lflag |= ECHO;

        tcsetattr(STDIN_FILENO, TCSANOW, &tty);
    }

    // Helper template for sizeof, since the compiler
    // doesn't like "sizeof(void)" - hence an explicit value assignment
    template <typename _T>
    constexpr size_t _sizeof_helper() {
        if constexpr (std::is_void_v<_T>)
            return 1;
        else
            return sizeof(_T);
    }

    // Securely zeroes memory at given pointer _T*, 
    // Note: no_of_freed_bytes = @size * sizeof(_T)
    // Beware! this function does NOT free the memory after zeroing!
    //
    // Input:
    // @ptr - span of memory of type _T
    template <typename _T, std::size_t _Extent = std::dynamic_extent>
    inline void secure_zero_memory(std::span<_T, _Extent> sp) {
        if (sp.data() != nullptr) {
            // zero the memory before freeing
            volatile uint8_t *vptr = reinterpret_cast<volatile uint8_t*>(sp.data());
            for (size_t i = 0; i < sp.size_bytes(); i++)
                vptr[i] = 0;

            #ifdef SECURE_FREE_DEBUG
            std::cerr << "[secure_free] Cleared " << total_size << " bytes at " << reinterpret_cast<void*>(ptr) << std::endl;
            #endif // SECURE_FREE_DEBUG
        }
    }

    template <typename _T>
    inline void secure_zero_memory(_T *ptr, size_t size) {
        if (ptr != nullptr) {
            volatile uint8_t *vptr = reinterpret_cast<volatile uint8_t*>(ptr);
            for (size_t i = 0; i < size; i++)
                vptr[i] = 0;

            #ifdef SECURE_FREE_DEBUG
            std::cerr << "[secure_free] Cleared " << total_size << " bytes at " << reinterpret_cast<void*>(ptr) << std::endl;
            #endif // SECURE_FREE_DEBUG
        }
    }

    // Concept for an object applicable to be securely deleted
    // it must have the data() and size() functions defined
    template <typename _T>
    concept SecureDeleteContainer = requires(_T &c) {
        typename _T::value_type;
        { c.data() } -> std::convertible_to<void*>;
        { c.size() } -> std::convertible_to<size_t>;
    };

    // Securely zeroes and deletes the container
    //
    // Input:
    // @ptr - raw pointer to the container object
    template <SecureDeleteContainer _Container>
    inline void secure_delete(_Container *ptr) {
        secure_zero_memory(std::span{*ptr});
        delete ptr;
    }

    template <typename _S>
    inline void secure_delete_struct(_S *s) {
        constexpr size_t size = sizeof(_S);
        secure_zero_memory(s, size);
        delete s;
    }

    // Securely zeroes and frees the memory
    // Note: no_of_freed_bytes = size * sizeof(_T)
    //
    // Input:
    // @ptr - pointer to the memory
    // @size - number of contiguous elements to zero-out (size() for containers)
    template <typename _T>
    inline void secure_free_memory(_T *ptr, size_t size) {
        secure_zero_memory(ptr, size);
        free(ptr);
    }

    // Initializes GMP to use secure memory deallocation
    inline void mpz_initialize_secure() {
        // Set custom memory deallocation function for GMP to ensure sensitive data is cleared from memory
        mp_set_memory_functions(
            nullptr, 
            nullptr, 
            secure_free_memory<void>
        );
    }
}