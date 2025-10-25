#pragma once

#include <memory>
#include <cstdint>
#include <gmpxx.h>

namespace ASN1 {
    class ASN1Object;
}

// Namespace containing RSA functionality
namespace RSA {

    // Header and footer of a valid PKCS#8 private key
    extern std::string PRIVATE_KEY_HEADER;
    extern std::string PRIVATE_KEY_FOOTER;

    // RSA Encryption OBJECT IDENTIFIER value
    extern std::string RSA_ENCRYPTION_OBJECT_IDENTIFIER;

    bool _RSAPrivateKey_format_check(std::shared_ptr<ASN1::ASN1Object> root_object);
    bool _RSAPrivateKey_is_supported(std::shared_ptr<ASN1::ASN1Object> root_object);

    // CRITICAL!!!
    // This function is a modification of free() call providing additional data zeroing for mpz_class objects
    void secure_free(void*, size_t);

    // Object representing an RSA private key (PKCS#1 compatibile)
    class RSAPrivateKey {
    private:
        uint32_t version;
        mpz_class n;
        mpz_class e;
        mpz_class d;
        mpz_class p;
        mpz_class q;
        mpz_class exponent1;
        mpz_class exponent2;
        mpz_class coefficient;

    public:
        static RSAPrivateKey from_file(std::string const &filepath);

        RSAPrivateKey(uint32_t version, mpz_class n, mpz_class e, mpz_class d,
            mpz_class p, mpz_class q, mpz_class exponent1, mpz_class exponent2, mpz_class coefficient)
            : version(version), n(n), e(e), d(d), p(p), q(q), 
            exponent1(exponent1), exponent2(exponent2), coefficient(coefficient) {
            if (version != 0) {
                throw std::runtime_error("Unsupported RSA private key version");
            }
        }

        RSAPrivateKey(std::string const &filepath)
            : RSAPrivateKey(from_file(filepath)) {}
    };
}