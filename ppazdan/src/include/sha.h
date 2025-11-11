#pragma once

#include <iostream>
#include <cstddef>
#include <cstdint>
#include <concepts>
#include <tuple>
#include <array>
#include <openssl/evp.h>
#include "include/debug.h"

namespace CBZ {

    // Different message digest sizes for various SHA variants
    typedef std::array<uint8_t, 28> MD224;
    typedef std::array<uint8_t, 32> MD256;

    // Concept of a hashing function
    // This essentially works as an interface and is used in other template objects
    // to check if given typename is compatibile with this, i.e. is a hashing function
    // (used by HMAC, for instance - see "hmac.h")
    template <typename _H>
    concept HashFunction = requires(_H& hash, const uint8_t *data, size_t size) {
        
        // First, check if the MD (Message Digest) type has been defined as a size variation
        // of type std::array<uint8_t, S> and if S > 0
        typename _H::MD; // Message Digest type (some are declared above, like MD224 or MD256)
        requires std::same_as<typename _H::MD::value_type, uint8_t>;
        requires (std::tuple_size_v<typename _H::MD> > 0);

        { _H::DIGEST_SIZE } -> std::convertible_to<size_t>; // Size of a hashing function's digest, in bytes
        { _H::BLOCK_SIZE } -> std::convertible_to<size_t>; // Size of a hashing function's internal block, in bytes
        { _H::digest(data, size) } -> std::same_as<typename _H::MD>; // Main functionality of a hash function - digest
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
        // @message - message to digest
        // @size - size of the message to digest
        template <typename _MD>
        _MD _SHA_digest_generic(EVP_MD *md, const char *class_name, uint8_t *message, size_t size);

        // SHA224 class
        class SHA224 {
        public:
            typedef MD224 MD;
            static constexpr size_t BLOCK_SIZE = 64;
            static constexpr size_t DIGEST_SIZE = std::tuple_size_v<MD>;

            SHA224() = delete;
            ~SHA224() = delete;
            static MD224 digest(uint8_t const *data, size_t size);
        };

        // SHA256 class
        class SHA256 {
        public:
            typedef MD256 MD;
            static constexpr size_t BLOCK_SIZE = 64;
            static constexpr size_t DIGEST_SIZE = 32;

            SHA256() = delete;
            ~SHA256() = delete;
            static MD256 digest(uint8_t const *data, size_t size);
        };

        // Wrapper class for EVP_MD* object, since it's declared as 'static' in every
        // function to avoid performance penalty, and thus needs to be freed on exit
        // BTW, the same happens for EVP_CIPHER - refer to "aes.h"
        // See: https://docs.openssl.org/3.2/man7/ossl-guide-libcrypto-introduction/#performance)
        class _EVP_MD_wrapper {
        private:
            EVP_MD *_md;

        public:
            // Fetch the message digest and optionally print a debug message
            _EVP_MD_wrapper(OSSL_LIB_CTX *ctx, const char *algorithm, const char *properties) 
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