#pragma once

#include <iostream>
#include <cstddef>
#include <cstdint>
#include <array>
#include <openssl/evp.h>
#include "include/debug.h"

namespace CBZ {

    // This namespace contains everything related to SHAs
    namespace SHA {

        // Different message digest sizes for various SHA variants
        typedef std::array<uint8_t, 28> MD224;
        typedef std::array<uint8_t, 32> MD256;

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
            // Get a SHA224 digest
            //
            // Input:
            // @data - data to digest
            // @size - size of that data
            static MD224 digest(uint8_t *data, size_t size);
        };

        // SHA256 class
        class SHA256 {
        public:
            // Get a SHA256 digest
            //
            // Input:
            // @data - data to digest
            // @size - size of that data
            static MD256 digest(uint8_t *data, size_t size);
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