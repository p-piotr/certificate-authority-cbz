#include <iostream>
#include <cstdint>
#include <vector>
#include <fstream>
#include <gmpxx.h>
#include "debug.h"
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
    std::string PRIVATE_KEY_HEADER = "-----BEGIN PRIVATE KEY-----";
    std::string PRIVATE_KEY_FOOTER = "-----END PRIVATE KEY-----";

    // RSA Encryption OBJECT IDENTIFIER - look at the beginning of this file
    std::string RSA_ENCRYPTION_OBJECT_IDENTIFIER = "1.2.840.113549.1.1.1";


    // Checks if the ASN.1 structure of the RSA private key is correct
    // Additionally decodes the RSAPrivateKey structure inside the OCTET STRING, if hasn't been done yet
    // Input:
    // @root_object - root ASN1Object representing the whole key
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
        if (algorithm->tag() != ASN1Tag::OBJECT_IDENTIFIER || algorithm->children().size() != 0 || parameters->tag() != ASN1Tag::NULL_TYPE) {
            return false;
        }

        auto private_key = root_object->children()[2];
        if (private_key->tag() != ASN1Tag::OCTET_STRING) {
            return false;
        }

        std::shared_ptr<ASN1Object> pk_sequence;
        if (private_key->children().size() == 0) {
            // decode the private_key according to the PKCS#1 structure, since the ASN.1 parser didn't do it (it's a Primitive OCTET STRING after all)
            pk_sequence = ASN1Parser::decode_all(private_key->value().buffer(), private_key->value().value_offset());
            if (pk_sequence->tag() != ASN1Tag::SEQUENCE || pk_sequence->children().size() != 9) {
                return false;
            }
            private_key->_children.push_back(pk_sequence);
        }
        else {
            // maybe it's not the first time we're checking this object, so it's been already decoded - just check if everything is intact
            pk_sequence = private_key->children()[0];
            if (pk_sequence->tag() != ASN1Tag::SEQUENCE || pk_sequence->children().size() != 9) {
                return false;
            }
        }

        for (auto child : pk_sequence->children()) {
            if (child->tag() != ASN1Tag::INTEGER || child->children().size() != 0) {
                return false;
            }
        }
        return true;
    }

    // Checks if the RSA private key is supported (version, algorithm OID)
    // Currently only version 0 and rsaEncryption algorithm are supported
    // Input:
    // @root_object - root ASN1Object representing the whole key
    bool _RSAPrivateKey_is_supported(std::shared_ptr<ASN1Object> root_object) {
        auto version = std::static_pointer_cast<ASN1::ASN1Integer>(root_object->children()[0]);
        if (version->value() != 0) {
            return false;
        }

        auto algorithm = std::static_pointer_cast<ASN1::ASN1ObjectIdentifier>(root_object->children()[1]->children()[0]);
        if (algorithm->value() != RSA_ENCRYPTION_OBJECT_IDENTIFIER) {
            return false;
        }
    
        return true;
    }

    // Loads an RSA private key from file
    // Input:
    // @filepath - path to the file containing the RSA private key in PKCS#8
    RSAPrivateKey RSAPrivateKey::from_file(std::string const &filepath) {
        std::ifstream keyfile(filepath);
        std::string line1, line2, key_asn1_b64 = "";

        // read the key file and complain if needed
        std::getline(keyfile, line1);
        if (line1 != PRIVATE_KEY_HEADER) {
            throw std::runtime_error("RSA private key header doesn't match the standard");
        }

        // read all lines till the end and append to key_asn1_b64, except the footer
        std::getline(keyfile, line1);
        while (std::getline(keyfile, line2)) { // read next line and append the previous one
            key_asn1_b64 += line1;
            line1 = line2;
        }

        if (line1 != PRIVATE_KEY_FOOTER) {
            throw std::runtime_error("RSA private key footer doesn't match the standard");
        }

        std::vector<uint8_t> key_asn1 = Base64::decode(key_asn1_b64);
        std::shared_ptr<ASN1Object> asn1_root = ASN1Parser::decode_all(std::move(key_asn1), 0);

        // validate the overall key ASN.1 structure
        if (!_RSAPrivateKey_format_check(asn1_root)) {
            throw std::runtime_error("RSA private key format check failed");
        }
        // validate the key contents (supported algorithm, version), since we are very picky in what we actually support
        if (!_RSAPrivateKey_is_supported(asn1_root)) {
            throw std::runtime_error("RSA private key format not supported");
        }

        // RSAPrivateKey sequence - https://www.rfc-editor.org/rfc/rfc8017.html#page-55
        auto pk_sequence = asn1_root->children()[2]->children()[0];
        std::vector<mpz_class> rsa_params(9);
        // iterate through all 9 integers and save them
        for (size_t i = 0; i < 9; i++) {
            auto integer_obj = std::static_pointer_cast<ASN1::ASN1Integer>(pk_sequence->children()[i]);
            rsa_params[i] = integer_obj->value();
        }

        #ifdef RSA_DEBUG
        std::cerr << "RSA Private Key parameters:" << std::endl;
        std::cerr << "Version: " << rsa_params[0] << std::endl;
        std::cerr << "Modulus (n): " << rsa_params[1] << std::endl;
        std::cerr << "Public Exponent (e): " << rsa_params[2] << std::endl;
        std::cerr << "Private Exponent (d): " << rsa_params[3] << std::endl;
        std::cerr << "Prime 1 (p): " << rsa_params[4] << std::endl;
        std::cerr << "Prime 2 (q): " << rsa_params[5] << std::endl;
        std::cerr << "Exponent1 (d mod (p-1)): " << rsa_params[6] << std::endl;
        std::cerr << "Exponent2 (d mod (q-1)): " << rsa_params[7] << std::endl;
        std::cerr << "Coefficient (q^-1 mod p): " << rsa_params[8] << std::endl;
        #endif // RSA_DEBUG

        // return the key object
        return RSAPrivateKey(
            std::move(rsa_params[0]),
            std::move(rsa_params[1]),
            std::move(rsa_params[2]),
            std::move(rsa_params[3]),
            std::move(rsa_params[4]),
            std::move(rsa_params[5]),
            std::move(rsa_params[6]),
            std::move(rsa_params[7]),
            std::move(rsa_params[8])
        );
    }
}