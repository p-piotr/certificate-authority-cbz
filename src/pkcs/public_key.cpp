#include <iostream>
#include <vector>
#include "asn1/asn1.h"
#include "pkcs/public_key.h"
#include "utils/utils.hpp"

namespace CBZ::PKCS {

    // Example: RSAPublicKey: = {n: 1234123412341234123412341234123413241234134, e: 12384123841239412342314823041234218}
    std::ostream& operator<<(std::ostream& os, const RSAPublicKey& pk){
        os << "RSAPublicKey: = {n: " << pk.n() << ", e: " << pk.e() << "}";
        return os;
    }

    RSAPublicKey::RSAPublicKey(ASN1Object root_object) {
        auto _semantics_failed = []() {
            CBZ::Utils::universal_throw("[RSAPublicKey::RSAPublicKey] Semantic check failed");
        };

        if (root_object.tag() != ASN1Tag::BIT_STRING) _semantics_failed();
        if (
            root_object.children().size() != 1 
            || root_object.children()[0].tag() != ASN1Tag::SEQUENCE
        ) _semantics_failed(); 
        const ASN1Object& seq = root_object.children()[0];
        if (
            seq.children().size() != 2
            || seq.children()[0].tag() != ASN1Tag::INTEGER
            || seq.children()[1].tag() != ASN1Tag::INTEGER
        ) _semantics_failed();

        // decode

        mpz_class n = static_cast<const ASN1Integer&>(seq.children()[0]).value();
        mpz_class e = static_cast<const ASN1Integer&>(seq.children()[1]).value();

        _n = std::move(n);
        _e = std::move(e);
    }

    ASN1Object RSAPublicKey::to_asn1() const {
        return ASN1BitString(
            ASN1Sequence({
                ASN1Integer(n()),
                ASN1Integer(e())
            }).encode()
        );
    }

    std::vector<uint8_t> RSAPublicKey::encode() const {
        return to_asn1().encode();
    }

    void RSAPublicKey::print() const {
        std::cout << "Modulus (n): " << n() << std::endl;
        std::cout << "Public Exponent (e): " << e() << std::endl;
    }
}