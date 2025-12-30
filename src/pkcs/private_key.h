#pragma once

#include <memory>
#include <cstdint>
#include <gmpxx.h>
#include <stdexcept>
#include "pkcs/pkcs.h"
#include "asn1/asn1.h"

namespace CBZ::PKCS {

    using namespace CBZ::ASN1;

    // Object representing an RSA private key (PKCS#1 compatible)
    //
    // Technically speaking, this object does not represent an RSA private key per se,
    // but rather the PKCS PrivateKeyInfo using rsaEncryption as the privateKeyAlgorithm
    // and without any attributes in 'attributes' field (rsaEncryption does not specify any)
    //
    // PrivateKeyInfo ::= SEQUENCE {
    //   version                   Version,
    //   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
    //   privateKey                PrivateKey,
    //   attributes           [0]  IMPLICIT Attributes OPTIONAL 
    // }
    //
    // See: https://datatracker.ietf.org/doc/html/rfc5208#section-5
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
            : _version(std::move(version)), _n(std::move(n)), _e(std::move(e)), _d(std::move(d)), _p(std::move(p)), _q(std::move(q)), 
            _exponent1(std::move(exponent1)), _exponent2(std::move(exponent2)), _coefficient(std::move(coefficient)) {
            if (version != 0) {
                throw std::runtime_error("[RSAPrivateKey::RSAPrivateKey] Unsupported RSA private key version");
            }
        }

        // Constructor loading key from file
        // Can only parse unencrypted keys
        RSAPrivateKey(std::string const& filepath)
            : RSAPrivateKey(from_file(filepath)) {}

        RSAPrivateKey(std::string const& filepath, std::string&& passphrase)
            : RSAPrivateKey(from_file_with_passphrase(filepath, std::move(passphrase))) {}

        inline const mpz_class& version() const {
            return _version;
        }

        inline const mpz_class& n() const {
            return _n;
        }

        inline const mpz_class& e() const {
            return _e;
        }

        inline const mpz_class& d() const {
            return _d;
        }

        inline const mpz_class& p() const {
            return _p;
        }

        inline const mpz_class& q() const {
            return _q;
        }

        inline const mpz_class& exponent1() const {
            return _exponent1;
        }

        inline const mpz_class& exponent2() const {
            return _exponent2;
        }

        inline const mpz_class& coefficient() const {
            return _coefficient;
        }

        // Prints the private key (use only for debugging purposes)
        void print() const;

        static RSAPrivateKey from_base64_buffer(std::string&& key_asn1_b64);

        // Loads a private key from file
        // This variant may parse either encrypted or unencrypted keys
        // If the key turns out to be encrypted, this function will prompt
        // for passphrase and call RSAPrivateKey::from_base64_buffer_with_passphrase
        //
        // Call this variant if you're not sure whether the key
        // is encrypted or not
        //
        // Input:
        // @filepath - path to the file containing the private key in PKCS#8
        static RSAPrivateKey from_file(const std::string& filepath);

        static RSAPrivateKey from_base64_buffer_with_passphrase(std::string&& key_asn1_b64, std::string&& passphrase);

        // Loads a private key from file
        // This variant may parse either encrypted or unencrypted keys
        // If used for unencrypted key, the function behaves exactly like
        // the overload specifically for unencrypted keys (the passphrase is omitted)
        //
        // Input:
        // @filepath - path to the file containing the private key in PKCS#8
        // @passphrase - passphrase used when the key turns out to be encrypted, as an rvalue
        //               - gets securely deleted when not needed anymore
        static RSAPrivateKey from_file_with_passphrase(const std::string& filepath, std::string&& passphrase);
    };

    // Checks if the ASN.1 structure of the RSA private key is correct
    // Additionally decodes the RSAPrivateKey structure inside the OCTET STRING, if hasn't been done yet
    //
    // Input:
    // @root_object - root ASN1Object representing the whole key
    int _RSAPrivateKey_check_and_expand(ASN1Object& root_object);

    // Checks if the ASN.1 structure of the encrypted RSA private key is correct
    // This function only checks the first two levels deep in the ASN.1 structure,
    // that is it checks for existence of:
    // - encryption algorithm
    //     - algorithm
    //     - parameters
    // - encrypted data
    //
    // For further checks and data extraction, use algorithm-specific functions from the PKCS namespace
    //
    // Input:
    // @root_object - root ASN1Object representing the whole key
    // @out_ptr - optional AlgorithmIdentifier pointer 
    //            to store the algorithm options
    int _EncryptedRSAPrivateKey_check(
        const ASN1Object& root_object,
        struct AlgorithmIdentifier* out_ptr
    );

    // Decodes the key according to the algorithm inside
    //
    // Input:
    // @asn1_root - root ASN1Object representing the key
    RSAPrivateKey _Decode_key(ASN1Object& asn1_root);

    // Decrypts private key using given algorithm
    //
    // Input:
    // @encrypted_data - encrypted data of the private key
    // @alg_id - pointer to the AlgorithmIdentifier structure
    //           specyfing algorithm to use 
    //           (most usually PKCS#5 PBES2) together with parameters
    // @passphrase - passphrase for decryption process to use, as an rvalue
    //               this value will be disposed securely after the function completes
    RSAPrivateKey _Decrypt_key(
        const ASN1Object& encrypted_data,
        const struct AlgorithmIdentifier* alg_id,
        std::string&& passphrase
    );


    class FeatureUnsupportedException : public std::runtime_error {
    public:
        explicit FeatureUnsupportedException(const char* const message)
            : std::runtime_error(message) {}
    };

    class AlgorithmUnsupportedException : public std::runtime_error {
    public:
        explicit AlgorithmUnsupportedException(const char* const message)
            : std::runtime_error(message) {}
    };

    class SemanticCheckException : public std::runtime_error {
    public:
        explicit SemanticCheckException(const char* const message)
            : std::runtime_error(message) {}
    };
}
