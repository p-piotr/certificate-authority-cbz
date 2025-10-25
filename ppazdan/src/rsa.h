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
    extern std::string private_key_header;
    extern std::string private_key_footer;

    // RSA Encryption OBJECT IDENTIFIER value
    extern std::string rsa_encryption_obj_id;

    bool _RSAPrivateKey_format_check(std::shared_ptr<ASN1::ASN1Object> root_object);

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

        RSAPrivateKey(uint32_t version, mpz_class n, mpz_class e, mpz_class d, mpz_class p, mpz_class q, mpz_class exponent1, mpz_class exponent2, mpz_class coefficient) : version(version), n(n), e(e), d(d), p(p), q(q), exponent1(exponent1), exponent2(exponent2), coefficient(coefficient) {
            if (version != 0) {
                throw std::runtime_error("Unsupported RSA private key version");
            }
        }

        RSAPrivateKey(std::string const &filepath) { 
            RSAPrivateKey key = RSAPrivateKey::from_file(filepath); 
            version = key.version;
            n = key.n;
            e = key.e;
            d = key.d;
            p = key.p;
            q = key.q;
            exponent1 = key.exponent1;
            exponent2 = key.exponent2;
            key.coefficient = key.coefficient;
        }
    };

}