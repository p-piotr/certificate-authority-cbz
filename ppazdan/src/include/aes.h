#pragma once

#include <iostream>
#include <vector>
#include <array>
#include <cstdint>
#include <cstddef>
#include <openssl/evp.h>
#include "include/debug.h"

namespace CBZ {

    // This namespace contains all stuff related to AES encryption
    namespace AES {

        // Multiple key sizes for use by different AES variants
        typedef std::array<uint8_t, 16> KEY128, IV; // IV is 128 bits for all variants, since the AES_BLOCK_SIZE = 128b
        typedef std::array<uint8_t, 24> KEY192;
        typedef std::array<uint8_t, 32> KEY256;

        // This is a generic AES encrypt template function capable 
        // of generating ciphertext for multiple key sizes (AES variants),
        // outputting ciphertext as a vector
        //
        // Input:
        // @cipher - EVP_CIPHER* cipher object used internally by OpenSSL
        // @class_name - name of the class implementing this template - used
        //               only to print clear error debug logs
        // @data - buffer to encrypt
        // @size - size of the buffer to encrypt
        // @key - template key object, can be chosen from the keys above
        // @iv - initialization vector for encryption to use
        template <typename _KEY>
        std::vector<uint8_t> _AES_encrypt_generic(
            EVP_CIPHER *cipher, 
            const char *class_name, 
            uint8_t *data, 
            size_t size, 
            _KEY &key,
            IV &iv
        );

        // Same as above, but for decrypting
        //
        // Input:
        // @cipher - EVP_CIPHER* cipher object used internally by OpenSSL
        // @class_name - name of the class implementing this template - used
        //               only to print clear error debug logs
        // @data - buffer to decrypt
        // @size - size of the buffer to decrypt
        // @key - template key object, can be chosen from { KEY128, KEY192, KEY256 }
        // @iv - initialization vector for decryption to use
        template <typename _KEY>
        std::vector<uint8_t> _AES_decrypt_generic(
            EVP_CIPHER *cipher,
            const char *class_name,
            uint8_t *data,
            size_t size,
            _KEY &key,
            IV &iv
        );

        // AES-128-CBC class
        class AES_128_CBC {
        public:
            
            // Encrypts data using AES-128-CBC
            //
            // Input:
            // @data - buffer to encrypt
            // @size - size of the buffer to encrypt
            // @key - 128bit key to use
            // @iv - initialization vector for encryption to use
            static std::vector<uint8_t> encrypt(uint8_t *data, size_t size, KEY128 &key, IV &iv);

            // Decrypts data using AES-128-CBC
            //
            // Input:
            // @data - buffer to decrypt
            // @size - size of the buffer to decrypt
            // @key - 128bit key to use
            // @iv - initialization vector for decryption to use
            static std::vector<uint8_t> decrypt(uint8_t *data, size_t size, KEY128 &key, IV &iv);
        };

        // AES-192-CBC class
        class AES_192_CBC {
        public:

            // Encrypts data using AES-192-CBC
            //
            // Input:
            // @data - buffer to encrypt
            // @size - size of the buffer to encrypt
            // @key - 192bit key to use
            // @iv - initialization vector for encryption to use
            static std::vector<uint8_t> encrypt(uint8_t *data, size_t size, KEY192 &key, IV &iv);

            // Decrypts data using AES-192-CBC
            //
            // Input:
            // @data - buffer to decrypt
            // @size - size of the buffer to decrypt
            // @key - 192bit key to use
            // @iv - initialization vector for decryption to use
            static std::vector<uint8_t> decrypt(uint8_t *data, size_t size, KEY192 &key, IV &iv);
        };

        // AES-256-CBC class
        class AES_256_CBC {
        public:

            // Encrypts data using AES-256-CBC
            //
            // Input:
            // @data - buffer to encrypt
            // @size - size of the buffer to encrypt
            // @key - 256bit key to use
            // @iv - initialization vector for encryption to use
            static std::vector<uint8_t> encrypt(uint8_t *data, size_t size, KEY256 &key, IV &iv);

            // Decrypts data using AES-256-CBC
            //
            // Input:
            // @data - buffer to decrypt
            // @size - size of the buffer to decrypt
            // @key - 256bit key to use
            // @iv - initialization vector for decryption to use
            static std::vector<uint8_t> decrypt(uint8_t *data, size_t size, KEY256 &key, IV &iv);
        };

        // Wrapper class for EVP_CIPHER* object, since it's declared as 'static' in every
        // function to avoid performance penalty, and thus needs to be freed on exit
        // BTW, the same happens for EVP_MD - refer to "sha.h"
        // See: https://docs.openssl.org/3.2/man7/ossl-guide-libcrypto-introduction/#performance)
        class _EVP_CIPHER_wrapper {
        private:
            EVP_CIPHER *_cipher;

        public:
            // Fetch the cipher and optionally print a debug message
            _EVP_CIPHER_wrapper(OSSL_LIB_CTX *ctx, const char *algorithm, const char *properties)
            : _cipher(EVP_CIPHER_fetch(ctx, algorithm, properties)) {
                #ifdef OPENSSL_DEBUG
                std::cerr << "[_EVP_CIPHER_wrapper] Fetched '" << algorithm << "' with properties '" 
                << (properties != nullptr ? properties : "(null)") << "'" << std::endl;
                #endif // OPENSSL_DEBUG
            }

            // Free the cipher and optionally print a debug message
            ~_EVP_CIPHER_wrapper() {
                EVP_CIPHER_free(_cipher);
                #ifdef OPENSSL_DEBUG
                std::cerr << "[_EVP_CIPHER_wrapper] Freed EVP_CIPHER object" << std::endl;
                #endif // OPENSSL_DEBUG
            }

            // Get raw pointer to the cipher itself
            constexpr EVP_CIPHER* cipher() {
                return _cipher;
            }
        };
    }
}