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
    //
    // Input:
    // @root_object - root ASN1Object representing the whole key
    bool _RSAPrivateKey_format_check(std::shared_ptr<ASN1::ASN1Object> root_object);

    // Checks if the RSA private key is supported (version, algorithm OID)
    // Currently only version 0 and rsaEncryption algorithm are supported
    //
    // Input:
    // @root_object - root ASN1Object representing the whole key
    bool _RSAPrivateKey_is_supported(std::shared_ptr<ASN1::ASN1Object> root_object);

    // Object representing an RSA private key (PKCS#1 compatibile)
    class RSAPrivateKey {
    private:
        mpz_class _version;
        mpz_class _n;
        mpz_class _e;
        mpz_class _d;
        mpz_class _p;
        mpz_class _q;
        mpz_class _exponent1;
        mpz_class _exponent2;
        mpz_class _coefficient;

    public:

        // Empty constructor
        RSAPrivateKey() : _version(0), _n(0), _e(0), _d(0), _p(0), _q(0), 
            _exponent1(0), _exponent2(0), _coefficient(0) {}

        // Basic constructor
        RSAPrivateKey(mpz_class version, mpz_class n, mpz_class e, mpz_class d,
            mpz_class p, mpz_class q, mpz_class exponent1, mpz_class exponent2, mpz_class coefficient)
            : _version(version), _n(n), _e(e), _d(d), _p(p), _q(q), 
            _exponent1(exponent1), _exponent2(exponent2), _coefficient(coefficient) {
            if (version != 0) {
                throw std::runtime_error("[RSAPrivateKey::RSAPrivateKey] Unsupported RSA private key version");
            }
        }

        // Constructor loading key from file
        RSAPrivateKey(std::string const &filepath)
            : RSAPrivateKey(from_file(filepath)) {}

        inline mpz_class version() const {
            return _version;
        }

        inline mpz_class n() const {
            return _n;
        }

        inline mpz_class e() const {
            return _e;
        }

        inline mpz_class d() const {
            return _d;
        }

        inline mpz_class p() const {
            return _p;
        }

        inline mpz_class q() const {
            return _q;
        }

        inline mpz_class exponent1() const {
            return _exponent1;
        }

        inline mpz_class exponent2() const {
            return _exponent2;
        }

        inline mpz_class coefficient() const {
            return _coefficient;
        }

        void print() {
            std::cout << "Version: " << version() << std::endl;
            std::cout << "Modulus (n): " << n() << std::endl;
            std::cout << "Public Exponent (e): " << e() << std::endl;
            std::cout << "Private Exponent (d): " << d() << std::endl;
            std::cout << "Prime 1 (p): " << p() << std::endl;
            std::cout << "Prime 2 (q): " << q() << std::endl;
            std::cout << "Exponent1 (d mod (p-1)): " << exponent1() << std::endl;
            std::cout << "Exponent2 (d mod (q-1)): " << exponent2() << std::endl;
            std::cout << "Coefficient (q^-1 mod p): " << coefficient() << std::endl;
        }

        // Loads an RSA private key from file
        //
        // Input:
        // @filepath - path to the file containing the RSA private key in PKCS#8
        static RSAPrivateKey from_file(std::string const &filepath);
    };
}