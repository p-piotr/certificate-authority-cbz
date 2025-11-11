#include <openssl/evp.h>
#include <array>
#include <stdexcept>
#include <sstream>
#include "include/sha.h"

namespace CBZ::SHA {

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
    _MD _SHA_digest_generic(EVP_MD *md, const char *class_name, uint8_t const *message, size_t size) {
        EVP_MD_CTX *ctx = nullptr;
        _MD outdigest;
        int ret = 1;

        ctx = EVP_MD_CTX_new();
        if (ctx == nullptr)
            goto err;

        if (md == nullptr)
            goto err;

        if (!EVP_DigestInit_ex(ctx, md, nullptr))
            goto err;

        if (!EVP_DigestUpdate(ctx, message, size))
            goto err;

        if (!EVP_DigestFinal_ex(ctx, outdigest.begin(), nullptr))
            goto err;

        ret = 0;

        err:
        EVP_MD_CTX_free(ctx);
        if (ret != 0) {
            std::stringstream err_msg;
            err_msg << "[" << class_name << "::digest] Error while digesting";
            throw std::runtime_error(err_msg.str());
        }
        
        return outdigest;
    }

    // See "sha.h" for further documentation, if needed

    MD224 SHA224::digest(uint8_t const *message, size_t size) {
        static _EVP_MD_wrapper sha224(nullptr, "SHA224", nullptr);
        return _SHA_digest_generic<MD224>(sha224.md(), "SHA224", message, size);
    }

    MD256 SHA256::digest(uint8_t const *message, size_t size) {
        static _EVP_MD_wrapper sha256(nullptr, "SHA256", nullptr);
        return _SHA_digest_generic<MD256>(sha256.md(), "SHA256", message, size);
    }
}