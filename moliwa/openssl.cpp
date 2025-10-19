
#include "openssl.h"


using std::string;
using std::vector;
using std::runtime_error;

//https://www.rfc-editor.org/rfc/rfc2313.html
//https://eprint.iacr.org/2018/855.pdf
//Sign = hash + padding + encrypt, it is kinda doable
vector<uint8_t> rsa_sha256_sign(const vector<uint8_t> &data, const string &private_key_path) {
    FILE *fp = fopen(private_key_path.c_str(), "r");
    if (!fp) throw runtime_error("Unable to open file: " + private_key_path);

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!pkey) throw runtime_error("Unable to parse private key");

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        throw runtime_error("Unable to create EVP_MD_CTX");
    }

    if (EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        throw runtime_error("EVP_DigestSignInit failed");
    }

    if (EVP_DigestSignUpdate(mdctx, data.data(), data.size()) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        throw runtime_error("EVP_DigestSignUpdate failed");
    }

    size_t siglen = 0;
    EVP_DigestSignFinal(mdctx, nullptr, &siglen);

    vector<uint8_t> signature(siglen);
    if (EVP_DigestSignFinal(mdctx, signature.data(), &siglen) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        throw runtime_error("EVP_DigestSignFinal failed");
    }


    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    return signature;
}

