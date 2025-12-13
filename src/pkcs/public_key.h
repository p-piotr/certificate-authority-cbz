#pragma once

#include <gmpxx.h>
#include <cstdint>
#include <vector>
#include <string>
#include "asn1/asn1.h"
#include "pkcs/private_key.h"

namespace CBZ::PKCS {

    // https://www.rfc-editor.org/rfc/rfc2313.html#section-7.1
    // 
    // RSAPublicKey ::= SEQUENCE {
    //   modulus INTEGER, -- n
    //   publicExponent INTEGER -- e
    // }
    class RSAPublicKey{
    private:
        mpz_class _n;
        mpz_class _e;
    public:
        // Empty constructor
        RSAPublicKey() : _n(0), _e(0) {}

        // Basic constructor
        RSAPublicKey(mpz_class n, mpz_class e) : _n(std::move(n)), _e(std::move(e)) {}

        // Derive it from a private key
        RSAPublicKey(RSAPrivateKey const& private_key)
            : _n(private_key.n()), _e(private_key.e()) {}

        ASN1::ASN1Object to_asn1() const;

        // returns RSAPublicKey as DER encoded bytes
        std::vector<uint8_t> encode() const;

        // getters
        inline mpz_class const& n() const { return _n; }
        inline mpz_class const& e() const { return _e; }

        // << operator
        friend std::ostream& operator<<(std::ostream& os, const RSAPublicKey& PK);
    };
}