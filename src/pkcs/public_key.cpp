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
        if (int result = _RSAPublicKey_check_and_expand(root_object); result != ERR_OK) _semantics_failed();
        const ASN1Object& seq = root_object.children()[0];

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

    int _RSAPublicKey_check_and_expand(ASN1Object& root_object) {
        auto _public_key_semantic_check = [&](const ASN1Object& _pk_sequence) {
            if (_pk_sequence.tag() != ASN1Tag::SEQUENCE) {
                return false;
            }
            if (_pk_sequence.children().size() != 2) {
                return false;
            }
            if (
                _pk_sequence.children()[0].tag() != ASN1Tag::INTEGER
                || _pk_sequence.children()[1].tag() != ASN1Tag::INTEGER
            ) {
                return false;
            }

            return true;
        };

        if (root_object.tag() != ASN1Tag::BIT_STRING) {
            return ERR_SEMANTIC_CHECK_FAILED;
        }

        if (root_object.children().size() != 0) {
            // public key has already been decoded - just check if everything
            // is intact
            if (!_public_key_semantic_check(root_object.children()[0])) {
                return ERR_SEMANTIC_CHECK_FAILED;
            }
            return ERR_OK;
        }
        // public key has not been yet decoded - do it now
        std::vector<uint8_t> pk_sequence_value = static_cast<ASN1BitString&>(root_object).value(); // copy
        ASN1Object pk_sequence = ASN1Object::decode(std::move(pk_sequence_value));

        if (!_public_key_semantic_check(pk_sequence)) {
            return ERR_SEMANTIC_CHECK_FAILED;
        }

        // push the new sequence as a child of BIT STRING
        root_object._children.push_back(pk_sequence);
        // zero-out the BIT STRING _value
        // (since we cannot have both _value and _children at the same time)
        CBZ::Security::secure_zero_memory(root_object._value);
        // and finally, resize the _value to 0
        root_object._value.resize(0);

        return ERR_OK;
    }
}