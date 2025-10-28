#pragma once

#include <cstdint>
#include <iostream>
#include <gmpxx.h>
#include "debug.h"

/*
 I only marked those functions as inline because
 the compiler complained about multiple definitions during linking
 and I really didn't give a fuck to create a separate .cpp file for them
*/

// Securely zeroes memory at given pointer
// Beware! this function does NOT free the memory after zeroing!
//
// Input:
// @ptr - pointer to memory
// @size - size of memory (in bytes)
inline void secure_zero_memory(void *ptr, size_t size) {
    if (ptr != nullptr) {
        // zero the memory before freeing
        volatile uint8_t *vptr = static_cast<volatile uint8_t*>(ptr);
        for (size_t i = 0; i < size; i++) {
            vptr[i] = 0;
        }

        #ifdef SECURE_FREE_DEBUG
        std::cerr << "[secure_free] Cleared " << size << " bytes at " << ptr << std::endl;
        #endif // SECURE_FREE_DEBUG
    }
}

// Securely zeroes and deletes the vector
//
// Input:
// @ptr - raw pointer to the vector
inline void secure_delete_vector(std::vector<uint8_t> *ptr) {
    secure_zero_memory(ptr->data(), ptr->size());
    delete ptr;
}

// Securely zeroes and frees the memory
//
// Input:
// @ptr - pointer to the memory
// @size - size of memory (in bytes)
inline void secure_free_memory(void *ptr, size_t size) {
    secure_zero_memory(ptr, size);
    free(ptr);
}

// Initializes GMP to use secure memory deallocation
inline void mpz_initialize_secure() {
    // Set custom memory deallocation function for GMP to ensure sensitive data is cleared from memory
    mp_set_memory_functions(
        nullptr, 
        nullptr, 
        secure_free_memory
    );
}