#include <vector>
#include <array>
#include <cstdint>
#include <cstddef>
#include <span>
#include <stdexcept>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include "include/aes.h"
#include "include/debug.h"

namespace CBZ::AES {

    // This is a generic AES encrypt template function capable 
    // of generating ciphertext for multiple key sizes (AES variants),
    // outputting ciphertext as a vector
    //
    // Input:
    // @cipher - EVP_CIPHER* cipher object used internally by OpenSSL
    // @class_name - name of the class implementing this template - used
    //               only to print clear error debug logs
    // @plaintext - buffer to encrypt
    // @key - key to use in the encryption process
    // @iv - initialization vector for encryption to use
    // @ciphertext - vector to store the output ciphertext
    template <typename _KEY>
    void _AES_encrypt_generic(
        EVP_CIPHER *cipher,
        const char *class_name,
        std::span<uint8_t const> plaintext,
        _KEY key,
        IV iv,
        std::vector<uint8_t> &ciphertext
    ) {
        #ifdef AES_DEBUG
        size_t key_size = 0;
        if (std::string(class_name) == "AES_128_CBC")
            key_size = 16;
        else if (std::string(class_name) == "AES_192_CBC")
            key_size = 24;
        else if (std::string(class_name) == "AES_256_CBC")
            key_size = 32;

        auto _dprint = [&](std::span<uint8_t const> s) {
            for (auto b : s)
                std::cerr << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b) << ' ';
            std::cerr << std::endl;
        };
        std::cerr << "[_AES_encrypt_generic]" << std::endl;
        std::cerr << "plaintext:" << std::endl;
        _dprint(plaintext);
        std::cerr << "key:" << std::endl;
        _dprint(std::span{key, key_size});
        std::cerr << "IV:" << std::endl;
        _dprint(std::span{iv, 16});
        std::cerr << std::endl;
        #endif // AES_DEBUG
        EVP_CIPHER_CTX *ctx;
        ciphertext.resize(plaintext.size() + AES_BLOCK_SIZE);
        int ciphertext_len, len = 0, ret = 1;

        ctx = EVP_CIPHER_CTX_new();
        if (ctx == nullptr)
            goto err;

        if (cipher == nullptr)
            goto err;

        if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key, iv) != 1)
            goto err;

        if (EVP_EncryptUpdate(
                ctx,
                ciphertext.data(),
                &len,
                plaintext.data(),
                static_cast<int>(plaintext.size())
                ) != 1
            )
            goto err;
        
        ciphertext_len = len;
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertext_len, &len) != 1)
            goto err;

        ciphertext_len += len;
        ciphertext.resize(ciphertext_len);
        ret = 0;
        
        err:
        EVP_CIPHER_CTX_free(ctx);
        if (ret != 0) {
            // Print the specific OpenSSL error
            std::stringstream err_msg;
            err_msg << "[" << class_name << "::decrypt] ";
            unsigned long e_code;
            while ((e_code = ERR_get_error()) != 0) {
                err_msg << "OpenSSL Error: " << ERR_error_string(e_code, NULL) << std::endl;
            }
            
            throw std::runtime_error(err_msg.str());
        }
    }

    // Same as above, but for decrypting
    //
    // Input:
    // Input:
    // @cipher - EVP_CIPHER* cipher object used internally by OpenSSL
    // @class_name - name of the class implementing this template - used
    //               only to print clear error debug logs
    // @in - buffer to decrypt
    // @key - key to use in the decryption process
    // @iv - initialization vector for decryption to use
    template<typename _KEY>
    void _AES_decrypt_generic(
        EVP_CIPHER *cipher, 
        const char *class_name, 
        std::span<uint8_t const> ciphertext,
        _KEY key, 
        IV iv,
        std::vector<uint8_t> &plaintext
    ) {
        #ifdef AES_DEBUG
        size_t key_size = 0;
        if (std::string(class_name) == "AES_128_CBC")
            key_size = 16;
        else if (std::string(class_name) == "AES_192_CBC")
            key_size = 24;
        else if (std::string(class_name) == "AES_256_CBC")
            key_size = 32;

        auto _dprint = [&](std::span<uint8_t const> s) {
            std::cerr << "(size=" << s.size() << ")" << std::endl;
            for (auto b : s)
                std::cerr << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b) << ' ';
            std::cerr << std::dec << std::endl;
        };
        std::cerr << "[_AES_decrypt_generic]" << std::endl;
        std::cerr << "ciphertext:" << std::endl;
        _dprint(ciphertext);
        std::cerr << "key:" << std::endl;
        _dprint(std::span{key, key_size});
        std::cerr << "IV:" << std::endl;
        _dprint(std::span{iv, 16});
        std::cerr << std::endl;
        #endif // AES_DEBUG
        EVP_CIPHER_CTX *ctx;
        plaintext.resize(ciphertext.size());
        int plaintext_len, len = 0, ret = 1;

        ctx = EVP_CIPHER_CTX_new();
        if (ctx == nullptr)
            goto err;

        if (cipher == nullptr)
            goto err;

        if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key, iv) != 1)
            goto err;

        if (EVP_DecryptUpdate(
                ctx,
                plaintext.data(),
                &len,
                ciphertext.data(),
                static_cast<int>(ciphertext.size())
                ) != 1
            )
            goto err;

        plaintext_len = len;
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + plaintext_len, &len) != 1)
            goto err;

        plaintext_len += len;
        plaintext.resize(plaintext_len);
        ret = 0;

        err:
        EVP_CIPHER_CTX_free(ctx);
        if (ret != 0) {
            // Print the specific OpenSSL error
            std::stringstream err_msg;
            err_msg << "[" << class_name << "::decrypt] ";
            unsigned long e_code;
            while ((e_code = ERR_get_error()) != 0) {
                err_msg << "OpenSSL Error: " << ERR_error_string(e_code, NULL) << std::endl;
            }
            
            throw std::runtime_error(err_msg.str());
        }
    }

    // For further documentation, see "aes.h"

    void AES_128_CBC::encrypt(
        std::span<uint8_t const> plaintext,
        KEY128 key,
        IV iv,
        std::vector<uint8_t> &ciphertext
    ) {
        static _EVP_CIPHER_wrapper aes128cbc(nullptr, "AES-128-CBC", nullptr);
        _AES_encrypt_generic<KEY128>(
            aes128cbc.cipher(),
            "AES_128_CBC",
            plaintext,
            key,
            iv,
            ciphertext
        );
    }

    void AES_192_CBC::encrypt(
        std::span<uint8_t const> plaintext,
        KEY192 key,
        IV iv,
        std::vector<uint8_t> &ciphertext
    ) {
        static _EVP_CIPHER_wrapper aes192cbc(nullptr, "AES-192-CBC", nullptr);
        _AES_encrypt_generic<KEY192>(
            aes192cbc.cipher(),
            "AES_192_CBC",
            plaintext,
            key,
            iv,
            ciphertext
        );
    }

    void AES_256_CBC::encrypt(
        std::span<uint8_t const> plaintext,
        KEY256 key,
        IV iv,
        std::vector<uint8_t> &ciphertext
    ) {
        static _EVP_CIPHER_wrapper aes256cbc(nullptr, "AES-256-CBC", nullptr);
        return _AES_encrypt_generic<KEY256>(
            aes256cbc.cipher(),
            "AES_256_CBC",
            plaintext,
            key,
            iv,
            ciphertext
        );
    }

    void AES_128_CBC::decrypt(
        std::span<uint8_t const> ciphertext,
        KEY128 key,
        IV iv,
        std::vector<uint8_t> &plaintext
    ) {
        static _EVP_CIPHER_wrapper aes128cbc(nullptr, "AES-128-CBC", nullptr);
        return _AES_decrypt_generic<KEY128>(
            aes128cbc.cipher(),
            "AES_128_CBC",
            ciphertext,
            key,
            iv,
            plaintext
        );
    }

    void AES_192_CBC::decrypt(
        std::span<uint8_t const> ciphertext,
        KEY192 key,
        IV iv,
        std::vector<uint8_t> &plaintext
    ) {
        static _EVP_CIPHER_wrapper aes192cbc(nullptr, "AES-192-CBC", nullptr);
        return _AES_decrypt_generic<KEY192>(
            aes192cbc.cipher(),
            "AES_192_CBC",
            ciphertext,
            key,
            iv,
            plaintext
        );
    }

    void AES_256_CBC::decrypt(
        std::span<uint8_t const> ciphertext,
        KEY256 key,
        IV iv,
        std::vector<uint8_t> &plaintext
    ) {
        static _EVP_CIPHER_wrapper aes256cbc(nullptr, "AES-256-CBC", nullptr);
        _AES_decrypt_generic<KEY256>(
            aes256cbc.cipher(),
            "AES_256_CBC",
            ciphertext,
            key,
            iv,
            plaintext
        );
    }
}