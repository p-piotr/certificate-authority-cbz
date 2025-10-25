#include <iostream>
#include <cstdint>
#include <vector>
#include <fstream>
#include <gmpxx.h>
#include "rsa.h"
#include "asn1.h"
#include "base64.h"

/*

https://datatracker.ietf.org/doc/html/rfc5208#section-5
https://www.rfc-editor.org/rfc/rfc8017.html#page-68

PrivateKeyInfo ::= SEQUENCE {
        version                   Version,
        privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
        privateKey                PrivateKey,
        attributes           [0]  IMPLICIT Attributes OPTIONAL
}

we only support rsaEncryption => algorithm = 1.2.840.113549.1.1.1 && parameters = NULL

*/

// Contains all functionality related to RSA
namespace RSA {

    using namespace ASN1;

    // Header and footer of a valid PKCS#8 private key
    std::string private_key_header = "-----BEGIN PRIVATE KEY-----";
    std::string private_key_footer = "-----END PRIVATE KEY-----";

    // RSA Encryption OBJECT IDENTIFIER - look at the beginning of this file
    std::string rsa_encryption_obj_id = "1.2.840.113549.1.1.1";

    bool _RSAPrivateKey_format_check(std::shared_ptr<ASN1Object> root_object) {
        if (root_object->tag() != ASN1Tag::SEQUENCE || root_object->children().size() != 3) {
            return false;
        }

        auto version = root_object->children()[0];
        if (version->tag() != ASN1Tag::INTEGER && version->children().size() != 0) {
            return false;
        }

        auto private_key_algorithm = root_object->children()[1];
        if (private_key_algorithm->tag() != ASN1Tag::SEQUENCE || private_key_algorithm->children().size() != 2) {
            return false;
        }

        auto algorithm = private_key_algorithm->children()[0];
        auto parameters = private_key_algorithm->children()[1];
        if (algorithm->tag() != ASN1Tag::OBJECT_IDENTIFIER || algorithm->children().size() != 0) {
            return false;
        }
        if (parameters->tag() != ASN1Tag::NULL_TYPE && parameters->tag() != ASN1Tag::SEQUENCE) {
            return false;
        }
        // skip the parameters SEQUENCE check since we won't support them anyways

        auto private_key = root_object->children()[2];
        if (private_key->tag() != ASN1Tag::OCTET_STRING) {
            return false;
        }

        if (private_key->children().size() == 0) {
            // decode the private_key
            auto pk_sequence = ASN1Parser::decode_all(private_key->value(), 0);
            if (pk_sequence->tag() != ASN1Tag::SEQUENCE || pk_sequence->children().size() != 9) {
                return false;
            }
            private_key->_children.push_back(pk_sequence);
        }
        auto pk_sequence = private_key->children()[0];
        if (pk_sequence->tag() != ASN1Tag::SEQUENCE || pk_sequence->children().size() != 9) {
            return false;
        }
        for (auto child : pk_sequence->children()) {
            if (child->tag() != ASN1Tag::INTEGER || child->children().size() != 0) {
                return false;
            }
        }
        return true;
    }

    bool _PrivateKey_is_supported(std::shared_ptr<ASN1Object> root_object) {
        auto version = std::static_pointer_cast<ASN1::ASN1Integer>(root_object->children()[0]);
        if (version->value() != 0) {
            return false;
        }
    }

    // Loads an RSA private key from file
    // TODO: finish
    RSAPrivateKey RSAPrivateKey::from_file(std::string const &filepath) {
        std::ifstream keyfile(filepath);
        std::string line1, line2, key_asn1_b64 = "";

        std::getline(keyfile, line1);
        if (line1 != private_key_header) {
            throw std::runtime_error("RSA private key header doesn't match the standard");
        }

        std::getline(keyfile, line1);
        while (std::getline(keyfile, line2)) {
            key_asn1_b64 += line1;
            line1 = line2;
        }

        std::vector<uint8_t> key_asn1 = Base64::decode(key_asn1_b64);
        std::shared_ptr<ASN1Object> asn1_root = ASN1Parser::decode_all(key_asn1, 0);
    }

}