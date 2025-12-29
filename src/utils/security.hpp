#pragma once

#include <cstdint>
#include <concepts>
#include <span>
#include <iostream>
#include <vector>
#include <cstdio>
#include <gmpxx.h>
#include "utils/utils.hpp"

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

    // Securely zeroes and deletes a structure
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



    #ifdef GMP_DEBUG
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
    #endif

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
    inline bool const_equal(const _R& arg1, const _R& arg2){
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

    // Securely reads contets from a file into an output buffer
    // 'Securely' means that the function does not leave behind
    // any uncleared intermediate buffers which may contain
    // leftover sensitive data
    //
    // If size of out_buf is smaller than file size (in bytes),
    // file size is returned as an error
    // Otherwise, on success, 0 is returned
    //
    // This function may throw exceptions regarding filesystem errors
    // (i.e. could not open a file, error while reading, etc.)
    // and thus needs to be wrapped in a 'try-catch' clause
    //
    // Input:
    // @filepath - path to a file to read
    // @out_buf - buffer to read the file contents into
    inline size_t secure_read_file(const char* filepath, std::span<std::byte> out_buf) {
        size_t file_size;

        try {
            file_size = CBZ::Utils::get_file_size(filepath);
        } catch (...) {
            std::throw_with_nested(std::runtime_error("[secure_read_file] Could not get file size"));
        }

        if (file_size > out_buf.size_bytes())
            return file_size; // error indicating how many bytes should be allocated in the return buffer

        FILE* fp = std::fopen(filepath, "rb");
        if (!fp) {
            throw std::runtime_error("[secure_read_file] Could not open a file");
        }

        std::setvbuf(fp, nullptr, _IONBF, 0);
        size_t bytes_read = std::fread(out_buf.data(), 1, file_size, fp);
        std::fclose(fp);

        if (bytes_read < file_size) {
            // either an error occurred, or the file was modified (shortened)
            // between our size check and read - either way throw
            secure_zero_memory(out_buf); // don't forget to zero memory before throwing
            throw std::runtime_error("[secure_read_file] Error while reading from a file; read less than the file's size");
        }

        return 0;
    }

}
