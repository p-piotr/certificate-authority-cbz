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

    // Checks if the ASN.1 structure of the RSA private key is correct
    // Input:
    // @root_object - root ASN1Object representing the whole key
    bool _RSAPrivateKey_format_check(std::shared_ptr<ASN1::ASN1Object> root_object);

    // Checks if the RSA private key is supported (version, algorithm OID)
    // Currently only version 0 and rsaEncryption algorithm are supported
    // Input:
    // @root_object - root ASN1Object representing the whole key
    bool _RSAPrivateKey_is_supported(std::shared_ptr<ASN1::ASN1Object> root_object);

    // CRITICAL!!!
    // This function is a modification of free() call providing additional data zeroing for mpz_class objects
    void secure_free(void*, size_t);

    // Object representing an RSA private key (PKCS#1 compatibile)
    class RSAPrivateKey {
    private:
        mpz_class version;
        mpz_class n;
        mpz_class e;
        mpz_class d;
        mpz_class p;
        mpz_class q;
        mpz_class exponent1;
        mpz_class exponent2;
        mpz_class coefficient;

    public:
        // Loads an RSA private key from file
        // Input:
        // @filepath - path to the file containing the RSA private key in PKCS#8
        static RSAPrivateKey from_file(std::string const &filepath);

        // Basic constructor
        RSAPrivateKey(mpz_class version, mpz_class n, mpz_class e, mpz_class d,
            mpz_class p, mpz_class q, mpz_class exponent1, mpz_class exponent2, mpz_class coefficient)
            : version(version), n(n), e(e), d(d), p(p), q(q), 
            exponent1(exponent1), exponent2(exponent2), coefficient(coefficient) {
            if (version != 0) {
                throw std::runtime_error("Unsupported RSA private key version");
            }
        }

        // Constructor loading the key from file
        RSAPrivateKey(std::string const &filepath)
            : RSAPrivateKey(from_file(filepath)) {}
    };
}