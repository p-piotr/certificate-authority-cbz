#include <openssl/evp.h>
#include <openssl/aes.h>
#include <vector>
#include <array>
#include <cstdint>
#include <cstddef>
#include <span>
#include <stdexcept>
#include <sstream>
#include "include/aes.h"

namespace CBZ::AES {

    // This is a generic AES encrypt template function capable 
    // of generating ciphertext for multiple key sizes (AES variants),
    // outputting ciphertext as a vector
    //
    // Input:
    // @cipher - EVP_CIPHER* cipher object used internally by OpenSSL
    // @class_name - name of the class implementing this template - used
    //               only to print clear error debug logs
    // @data - buffer to encrypt
    // @key - key to use in the encryption process
    // @iv - initialization vector for encryption to use
    template <typename _KEY>
    std::vector<uint8_t> _AES_encrypt_generic(
        EVP_CIPHER *cipher,
        const char *class_name,
        std::span<uint8_t const> data,
        _KEY key,
        IV iv
    ) {
        EVP_CIPHER_CTX *ctx;
        std::vector<uint8_t> ciphertext(data.size() + AES_BLOCK_SIZE);
        int ciphertext_len, len = 0, ret = 1;

        ctx = EVP_CIPHER_CTX_new();
        if (ctx == nullptr)
            goto err;

        if (cipher == nullptr)
            goto err;

        if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key, iv) != 1)
            goto err;

        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, data.data(), static_cast<int>(data.size())) != 1)
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
            std::stringstream err_msg;
            err_msg << "[" << class_name << "::encrpyt] Error while encrypting";
            throw std::runtime_error(err_msg.str());
        }
        
        return ciphertext;
    }

    // Same as above, but for decrypting
    //
    // Input:
    // Input:
    // @cipher - EVP_CIPHER* cipher object used internally by OpenSSL
    // @class_name - name of the class implementing this template - used
    //               only to print clear error debug logs
    // @data - buffer to decrypt
    // @key - key to use in the decryption process
    // @iv - initialization vector for decryption to use
    template<typename _KEY>
    std::vector<uint8_t> _AES_decrypt_generic(
        EVP_CIPHER *cipher, 
        const char *class_name, 
        std::span<uint8_t const> data,
        _KEY key, 
        IV iv
    ) {
        EVP_CIPHER_CTX *ctx;
        std::vector<uint8_t> plaintext(data.size());
        int plaintext_len, len = 0, ret = 1;

        ctx = EVP_CIPHER_CTX_new();
        if (ctx == nullptr)
            goto err;

        if (cipher == nullptr)
            goto err;

        if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key, iv) != 1)
            goto err;

        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, data.data(), static_cast<int>(data.size())) != 1)
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
            std::stringstream err_msg;
            err_msg << "[" << class_name << "::decrpyt] Error while decrypting";
            throw std::runtime_error(err_msg.str());
        }

        return plaintext;
    }

    // For further documentation, see "aes.h"

    std::vector<uint8_t> AES_128_CBC::encrypt(std::span<uint8_t const> data, KEY128 key, IV iv) {
        static _EVP_CIPHER_wrapper aes128cbc(nullptr, "AES-128-CBC", nullptr);
        return _AES_encrypt_generic<KEY128>(aes128cbc.cipher(), "AES_128_CBC", data, key, iv);
    }

    std::vector<uint8_t> AES_192_CBC::encrypt(std::span<uint8_t const> data, KEY192 key, IV iv) {
        static _EVP_CIPHER_wrapper aes192cbc(nullptr, "AES-192-CBC", nullptr);
        return _AES_encrypt_generic<KEY192>(aes192cbc.cipher(), "AES_192_CBC", data, key, iv);
    }

    std::vector<uint8_t> AES_256_CBC::encrypt(std::span<uint8_t const> data, KEY256 key, IV iv) {
        static _EVP_CIPHER_wrapper aes256cbc(nullptr, "AES-256-CBC", nullptr);
        return _AES_encrypt_generic<KEY256>(aes256cbc.cipher(), "AES_256_CBC", data, key, iv);
    }

    std::vector<uint8_t> AES_128_CBC::decrypt(std::span<uint8_t const> data, KEY128 key, IV iv) {
        static _EVP_CIPHER_wrapper aes128cbc(nullptr, "AES-128-CBC", nullptr);
        return _AES_decrypt_generic<KEY128>(aes128cbc.cipher(), "AES_128_CBC", data, key, iv);
    }

    std::vector<uint8_t> AES_192_CBC::decrypt(std::span<uint8_t const> data, KEY192 key, IV iv) {
        static _EVP_CIPHER_wrapper aes192cbc(nullptr, "AES-192-CBC", nullptr);
        return _AES_decrypt_generic<KEY192>(aes192cbc.cipher(), "AES_192_CBC", data, key, iv);
    }

    std::vector<uint8_t> AES_256_CBC::decrypt(std::span<uint8_t const> data, KEY256 key, IV iv) {
        static _EVP_CIPHER_wrapper aes256cbc(nullptr, "AES-256-CBC", nullptr);
        return _AES_decrypt_generic<KEY256>(aes256cbc.cipher(), "AES_256_CBC", data, key, iv);
    }
}