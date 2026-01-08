#pragma once

#include <iostream>
#include <vector>
#include <array>
#include <cstdint>
#include <cstddef>
#include <span>
#include <openssl/evp.h>

namespace CBZ {

    // This namespace contains all stuff related to AES encryption
    namespace AES {

        typedef uint8_t const* KEY128;
        typedef uint8_t const* KEY192;
        typedef uint8_t const* KEY256;
        typedef uint8_t const* IV;

        // This is a generic AES encrypt template function capable 
        // of generating ciphertext for multiple key sizes (AES variants),
        // outputting ciphertext as a vector
        //
        // Input:
        // @cipher - EVP_CIPHER* cipher object used internally by OpenSSL
        // @class_name - name of the class implementing this template - used
        //               only to print clear error debug logs
        // @plaintext - buffer to encrypt
        // @key - key to use in encryption process
        // @iv - initialization vector for encryption to use
        // @ciphertext - vector to store output ciphertext
        template<typename _KEY>
        void _AES_encrypt_generic(
            EVP_CIPHER* cipher, 
            char const* class_name, 
            std::span<uint8_t const> plaintext,
            _KEY key,
            IV iv,
            std::vector<uint8_t>& ciphertext
        );

        // Same as above, but for decrypting
        //
        // Input:
        // @cipher - EVP_CIPHER* cipher object used internally by OpenSSL
        // @class_name - name of the class implementing this template - used
        //               only to print clear error debug logs
        // @ciphertext - buffer to decrypt
        // @key - key to use in encryption process
        // @iv - initialization vector for decryption to use
        // @plaintext - vector to store output plaintext
        template<typename _KEY>
        void _AES_decrypt_generic(
            EVP_CIPHER* cipher,
            char const* class_name,
            std::span<uint8_t const> ciphertext,
            _KEY key,
            IV iv,
            std::vector<uint8_t>& plaintext
        );

        // AES-128-CBC class
        class AES_128_CBC {
        public:
            
            // Encrypts data using AES-128-CBC
            //
            // Input:
            // @plaintext - buffer to encrypt
            // @key - 128bit key to use
            // @iv - initialization vector for encryption to use
            // @ciphertext - vector to store output ciphertext
            static void encrypt(
                std::span<uint8_t const> plaintext,
                KEY128 key,
                IV iv,
                std::vector<uint8_t>& ciphertext
            );

            // Decrypts data using AES-128-CBC
            //
            // Input:
            // @ciphertext - buffer to decrypt
            // @key - 128bit key to use
            // @iv - initialization vector for decryption to use
            // @plaintext - vector to store output plaintext
            static void decrypt(
                std::span<uint8_t const> ciphertext,
                KEY128 key,
                IV iv,
                std::vector<uint8_t>& plaintext
            );
        };

        // AES-192-CBC class
        class AES_192_CBC {
        public:

            // Encrypts data using AES-192-CBC
            //
            // Input:
            // @plaintext - buffer to encrypt
            // @key - 192bit key to use
            // @iv - initialization vector for encryption to use
            // @ciphertext - vector to store output ciphertext
            static void encrypt(
                std::span<uint8_t const> plaintext,
                KEY192 key,
                IV iv,
                std::vector<uint8_t>& ciphertext
            );

            // Decrypts data using AES-192-CBC
            //
            // Input:
            // @ciphertext - buffer to decrypt
            // @key - 192bit key to use
            // @iv - initialization vector for decryption to use
            // @plaintext - vector to store output plaintext
            static void decrypt(
                std::span<uint8_t const> ciphertext,
                KEY192 key,
                IV iv,
                std::vector<uint8_t>& plaintext
            );
        };

        // AES-256-CBC class
        class AES_256_CBC {
        public:

            // Encrypts data using AES-256-CBC
            //
            // Input:
            // @plaintext - buffer to encrypt
            // @key - 256bit key to use
            // @iv - initialization vector for encryption to use
            // @ciphertext - vector to store output ciphertext
            static void encrypt(
                std::span<uint8_t const> plaintext,
                KEY256 key,
                IV iv,
                std::vector<uint8_t>& ciphertext
            );

            // Decrypts data using AES-256-CBC
            //
            // Input:
            // @ciphertext - buffer to decrypt
            // @key - 256bit key to use
            // @iv - initialization vector for decryption to use
            // @plaintext - vector to store output plaintext
            static void decrypt(
                std::span<uint8_t const> ciphertext,
                KEY256 key,
                IV iv,
                std::vector<uint8_t>& plaintext
            );
        };

        // Wrapper class for EVP_CIPHER* object, since it's declared as 'static' in every
        // function to avoid performance penalty, and thus needs to be freed on exit
        // BTW, the same happens for EVP_MD - refer to "sha.h"
        // See: https://docs.openssl.org/3.2/man7/ossl-guide-libcrypto-introduction/#performance)
        class _EVP_CIPHER_wrapper {
        private:
            EVP_CIPHER* _cipher;

        public:
            // Fetch the cipher and optionally print a debug message
            _EVP_CIPHER_wrapper(OSSL_LIB_CTX* ctx, char const* algorithm, char const* properties)
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