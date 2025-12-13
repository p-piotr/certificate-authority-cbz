#include <array>
#include <stdexcept>
#include <sstream>
#include <span>
#include <openssl/evp.h>
#include "hash/sha.h"

namespace CBZ::SHA {

    // This is a generic SHA digest template function capable 
    // of digesting messages for multiple digest sizes,
    // outputting the digest itself as some MD - see above
    //
    // Input:
    // @md - EVP_MD* message digest object used internally by OpenSSL
    // @class_name - name of the class implementing this template - used
    //               only to print clear error debug logs
    // @m - message to digest
    // @od - pointer to the buffer storing digest; it MUST
    //               be able to contain at least DIGEST_SIZE bytes
    void _SHA_digest_generic(
        EVP_MD* md,
        char const* class_name,
        std::span<uint8_t const> m,
        uint8_t* od
    ) {
        EVP_MD_CTX* ctx = nullptr;
        int ret = 1;

        ctx = EVP_MD_CTX_new();
        if (ctx == nullptr)
            goto err;

        if (md == nullptr)
            goto err;

        if (!EVP_DigestInit_ex(ctx, md, nullptr))
            goto err;

        if (!EVP_DigestUpdate(ctx, m.data(), m.size()))
            goto err;

        if (!EVP_DigestFinal_ex(ctx, od, nullptr))
            goto err;

        ret = 0;

        err:
        EVP_MD_CTX_free(ctx);
        if (ret != 0) {
            std::stringstream err_msg;
            err_msg << "[" << class_name << "::digest] Error while digesting";
            throw std::runtime_error(err_msg.str());
        }
    }

    // See "sha.h" for further documentation, if needed

    void SHA1::digest(std::span<uint8_t const> m, uint8_t* od) {
        static _EVP_MD_wrapper sha1(nullptr, "SHA1", nullptr);
        _SHA_digest_generic(sha1.md(), "SHA1", m, od);
    }

    void SHA224::digest(std::span<uint8_t const> m, uint8_t* od) {
        static _EVP_MD_wrapper sha224(nullptr, "SHA224", nullptr);
        _SHA_digest_generic(sha224.md(), "SHA224", m, od);
    }

    void SHA256::digest(std::span<uint8_t const> m, uint8_t* od) {
        static _EVP_MD_wrapper sha256(nullptr, "SHA256", nullptr);
        _SHA_digest_generic(sha256.md(), "SHA256", m, od);
    }
}