#pragma once

#include <iostream>
#include <span>
#include <cstddef>
#include <cstdint>
#include <concepts>
#include <tuple>
#include <array>
#include <openssl/evp.h>

namespace CBZ {

    // Concept of a hashing function
    // This essentially works as an interface and is used in other template objects
    // to check if given typename is compatibile with this, i.e. is a hashing function
    // (used by HMAC, for instance - see "hmac.h")
    template<typename _H>
    concept HashFunction = requires(
        std::span<uint8_t const> m,
        uint8_t* od
    ) {
        { _H::DIGEST_SIZE } -> std::convertible_to<size_t>; // Size of a hashing function's digest, in bytes
        { _H::BLOCK_SIZE } -> std::convertible_to<size_t>; // Size of a hashing function's internal block, in bytes
        // Check if the MD (Message Digest) type has been defined as a size variation
        // of type std::array<uint8_t, S> and if S > 0

        { _H::digest(m, od) } -> std::same_as<void>; // Main functionality of a hash function - digest
    };

    // This namespace contains everything related to SHAs
    namespace SHA {

        // This is a generic SHA digest template function capable 
        // of digesting messages for multiple digest sizes,
        // outputting the digest itself as some MD - see above
        //
        // Input:
        // @md - EVP_MD* message digest object used internally by OpenSSL
        // @class_name - name of the class implementing this template - used
        //               only to print clear error debug logs
        // @m - message to digest
        // @s - size of the message to digest
        // @od - pointer to the buffer storing digest; it MUST
        //               be able to contain at least DIGEST_SIZE bytes
        void _SHA_digest_generic(
            EVP_MD* md,
            char const* class_name,
            std::span<uint8_t const> m,
            uint8_t* od
        );

        // SHA1 class
        class SHA1 {
        public:
            static const constexpr size_t BLOCK_SIZE = 64;
            static const constexpr size_t DIGEST_SIZE = 20;

            SHA1() = delete;
            ~SHA1() = delete;
            static void digest(std::span<uint8_t const> m, uint8_t* od);
        };

        // SHA224 class
        class SHA224 {
        public:
            static const constexpr size_t BLOCK_SIZE = 64;
            static const constexpr size_t DIGEST_SIZE = 28;

            SHA224() = delete;
            ~SHA224() = delete;
            static void digest(std::span<uint8_t const> m, uint8_t* od);
        };

        // SHA256 class
        class SHA256 {
        public:
            static const constexpr size_t BLOCK_SIZE = 64;
            static const constexpr size_t DIGEST_SIZE = 32;

            SHA256() = delete;
            ~SHA256() = delete;
            static void digest(std::span<uint8_t const> m, uint8_t* od);
        };

        // Wrapper class for EVP_MD* object, since it's declared as 'static' in every
        // function to avoid performance penalty, and thus needs to be freed on exit
        // BTW, the same happens for EVP_CIPHER - refer to "aes.h"
        // See: https://docs.openssl.org/3.2/man7/ossl-guide-libcrypto-introduction/#performance)
        class _EVP_MD_wrapper {
        private:
            EVP_MD* _md;

        public:
            // Fetch the message digest and optionally print a debug message
            _EVP_MD_wrapper(OSSL_LIB_CTX* ctx, const char* algorithm, const char* properties) 
            : _md(EVP_MD_fetch(ctx, algorithm, properties)) {
                #ifdef OPENSSL_DEBUG
                std::cerr << "[_EVP_MD_wrapper] Fetched '" << algorithm << "' with properties '" 
                << (properties != nullptr ? properties : "(null)") << "'" << std::endl;
                #endif // OPENSSL_DEBUG
            }

            // Free the message digest and optionally print a debug message
            ~_EVP_MD_wrapper() {
                EVP_MD_free(_md);
                #ifdef OPENSSL_DEBUG
                std::cerr << "[_EVP_MD_wrapper] Freed EVP_MD object" << std::endl;
                #endif // OPENSSL_DEBUG
            }

            constexpr EVP_MD* md() {
                return _md;
            }
        };
    }
}