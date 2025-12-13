#include <iostream>
#include <cstdint>
#include <cstddef>
#include <vector>
#include <fstream>
#include <sstream>
#include <span>
#include <gmpxx.h>
#include "utils/security.hpp"
#include "pkcs/private_key.h"
#include "asn1/asn1.h"
#include "utils/base64.h"
#include "pkcs/pkcs.h"

/*

https://datatracker.ietf.org/doc/html/rfc5208#section-5
https://www.rfc-editor.org/rfc/rfc8017.html#page-68

PrivateKeyInfo ::= SEQUENCE {
        version                   Version,
        privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
        privateKey                PrivateKey,
        attributes           [0]  IMPLICIT Attributes OPTIONAL
}

*/

// Contains all functionality related to RSA
namespace CBZ::PKCS {

    using namespace CBZ::ASN1;
    using namespace CBZ::Security;

    // Checks if the ASN.1 structure of the RSA private key is correct
    // Additionally expands the key by decoding the RSAPrivateKey structure
    // inside the OCTET STRING according to the algorithm, if hasn't been done yet
    //
    // Input:
    // @root_object - root ASN1Object representing the whole key
    int _RSAPrivateKey_check_and_expand(std::shared_ptr<ASN1Object> root_object) {
        using namespace SupportedAlgorithms;

        // Root object should contain 3 or 4 children (attributies field is optional)
        if (
            root_object->tag() != ASN1Tag::SEQUENCE
            || root_object->children().size() < 3
            || root_object->children().size() > 4
        )
            return ERR_SEMANTIC_CHECK_FAILED;

        auto version = root_object->children()[0];
        auto private_key_algorithm = root_object->children()[1];
        auto private_key = root_object->children()[2];

        if (version->tag() != ASN1Tag::INTEGER) // 'version' must be of type INTEGER
            return ERR_SEMANTIC_CHECK_FAILED;
        if (std::static_pointer_cast<ASN1Integer>(version)->value() != 0) // 'version' must be equal to 0
            return ERR_FEATURE_UNSUPPORTED;
        if (private_key_algorithm->tag() != ASN1Tag::SEQUENCE) // 'private_key_algorithm' must be of type SEQUENCE
            return ERR_SEMANTIC_CHECK_FAILED;
        if (private_key->tag() != ASN1Tag::OCTET_STRING) // 'private_key' must be of type OCTET_STRING
            return ERR_SEMANTIC_CHECK_FAILED;

        // Now proceed to the algorithm extraction
        struct AlgorithmIdentifier alg_id;
        if (
            int result = PrivateKeyAlgorithms::extract_algorithm(private_key_algorithm, &alg_id);
            result != 0
        )
            return result;
        
        // Iterate through supported algorithms and act accordingly
        switch (alg_id.algorithm) {
            case PrivateKeyAlgorithms::rsaEncryption: {
                // According to the rsaEncryption PKCS specification, the private_key OCTET STRING
                // is actually a SEQUENCE containing 9 INTEGERs
                std::shared_ptr<ASN1Object> pk_sequence;
                if (private_key->children().size() == 0) {
                    // Decode the private_key according to the PKCS#1 structure, since
                    // the ASN.1 parser didn't do it (it's a Primitive OCTET STRING after all)
                    pk_sequence = ASN1Parser::decode_all(std::move(private_key->value()));
                    if (pk_sequence->children().size() != 9)
                        return ERR_SEMANTIC_CHECK_FAILED;

                    private_key->_children.push_back(pk_sequence);
                } else if (private_key->children()[0]->children().size() != 9)
                    return ERR_SEMANTIC_CHECK_FAILED;

                return ERR_OK;
            }
            default:
                return ERR_ALGORITHM_UNSUPPORTED;
        }
    }

    // Checks if the ASN.1 structure of the encrypted RSA private key is correct
    //
    // Input:
    // @root_object - root ASN1Object representing the whole key
    // @out_ptr - optional pointer to the AlgorithmIdentifier structure
    //            to store the extracted algorithm
    int _EncryptedRSAPrivateKey_check(
        std::shared_ptr<ASN1Object const> root_object,
        struct AlgorithmIdentifier* out_ptr
    ) {
        using namespace SupportedAlgorithms;

        if (root_object->tag() != ASN1Tag::SEQUENCE || root_object->children().size() != 2)
            return ERR_SEMANTIC_CHECK_FAILED;
        
        auto encryption_algorithm = root_object->children()[0];
        auto encrypted_data = root_object->children()[1];
        
        if (int result = EncryptionAlgorithms::extract_algorithm(encryption_algorithm, out_ptr); result != ERR_OK)
            return result;
        if (encrypted_data->tag() != ASN1Tag::OCTET_STRING)
            return ERR_SEMANTIC_CHECK_FAILED;

        return ERR_OK;
    }

    RSAPrivateKey _Decrypt_key(
        std::shared_ptr<ASN1Object> encrypted_data,
        struct AlgorithmIdentifier const* alg_id,
        std::string&& passphrase
    ) {
        using namespace SupportedAlgorithms;

        std::shared_ptr<std::string> passphrase_sp(
            new std::string(std::move(passphrase)),
            secure_delete<std::string>
        );
        std::shared_ptr<std::vector<uint8_t>> decrypted_data(
            new std::vector<uint8_t>(),
            secure_delete<std::vector<uint8_t>>
        );

        auto params = std::static_pointer_cast<EncryptionAlgorithms::PBES2::Parameters>
            (alg_id->params);
        switch (alg_id->algorithm) {
            case EncryptionAlgorithms::pbes2: {
                if (
                    int result = EncryptionAlgorithms::PBES2::decrypt_data(
                        params.get(),
                        passphrase_sp,
                        std::span{encrypted_data->value()},
                        *decrypted_data
                    ); result != ERR_OK
                ) {
                    switch (result) {
                        case ERR_SEMANTIC_CHECK_FAILED:
                            throw SemanticCheckException("Semantic check in RSA private key failed");
                        case ERR_ALGORITHM_UNSUPPORTED:
                            throw AlgorithmUnsupportedException("Algorithm used in RSA private key is unsupported");
                        case ERR_FEATURE_UNSUPPORTED:
                            throw FeatureUnsupportedException("Feature used inside RSA private key is unsupported");
                        default:
                            throw std::runtime_error("Unspecified exception was thrown while decrypting RSA private key");
                    }
                }
                break;
            }
            default:
                throw AlgorithmUnsupportedException("Algorithm used in RSA private key is unsupported");
        }

        auto root_object = ASN1Parser::decode_all(*decrypted_data);

        // finally, decode the decrypted key and return it
        return _Decode_key(root_object);
    }


    // Prints the private key (use only for debugging purposes)
    void RSAPrivateKey::print() {
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

    RSAPrivateKey _Decode_key(std::shared_ptr<ASN1Object> asn1_root) {
        // validate the overall key ASN.1 structure and expand it, if needed
        if (int result = _RSAPrivateKey_check_and_expand(asn1_root); result != 0) {
            switch (result) {
                case ERR_SEMANTIC_CHECK_FAILED:
                    throw SemanticCheckException("[RSAPrivateKey::from_file] RSA private key semantic check failed");
                case ERR_FEATURE_UNSUPPORTED:
                    throw FeatureUnsupportedException("[RSAPrivateKey::from_file] RSA private key feature is unsupported");
                case ERR_ALGORITHM_UNSUPPORTED:
                    throw AlgorithmUnsupportedException("[RSAPrivateKey::from_file] RSA private key algorithm is unsupported");
                default:
                    throw std::runtime_error("[RSAPrivateKey::from_file] RSA private key unknown error");
            }
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

    // Loads a private key from file
    // This variant may only parse unencryptd keys
    //
    // Input:
    // @filepath - path to the file containing the private key in PKCS#8
    RSAPrivateKey RSAPrivateKey::from_file(std::string const& filepath) {
        std::ifstream keyfile(filepath);
        std::string line1, line2, key_asn1_b64 = "";

        // read the key file and complain if needed
        std::getline(keyfile, line1);
        if (line1 == PKCS::Labels::encryptedPrivateKeyHeader) {
            // the header says it's encrypted, so let's try to parse it accordingly
            std::string passphrase;
            std::cout << "Enter passphrase: ";
            set_stdin_echo(false);
            std::cin >> passphrase;
            set_stdin_echo(true);
            std::cout << std::endl;
            return from_file(filepath, std::move(passphrase));
        }
        if (line1 != PKCS::Labels::privateKeyHeader)
            throw SemanticCheckException("[RSAPrivateKey::from_file] RSA private key header doesn't match the standard");

        // read all lines till the end and append to key_asn1_b64, except the footer
        std::getline(keyfile, line1);
        while (std::getline(keyfile, line2)) { // read next line and append the previous one
            key_asn1_b64 += line1;
            line1 = line2;
        }

        if (line1 != PKCS::Labels::privateKeyFooter)
            throw SemanticCheckException("[RSAPrivateKey::from_file] RSA private key footer doesn't match the standard");

        std::vector<uint8_t> key_asn1 = Base64::decode(key_asn1_b64);
        std::shared_ptr<ASN1Object> asn1_root = ASN1Parser::decode_all(std::move(key_asn1));

        // decode the final expanded structure into 9 integers
        return _Decode_key(asn1_root);
    }
    
    RSAPrivateKey RSAPrivateKey::from_file(std::string const& filepath, std::string&& passphrase) {
        std::ifstream keyfile(filepath);
        std::string line1, line2, key_asn1_b64 = "";

        std::getline(keyfile, line1);
        if (line1 == PKCS::Labels::privateKeyHeader) {
            // i don't know why, but it seems this key is unencrypted, although we received a password for it
            // assume this key is unencrypted and it was a mistake - discard the password and proceed with the
            // unencrypted procedure
            secure_zero_memory(passphrase);
            return from_file(filepath);
        }
        if (line1 != PKCS::Labels::encryptedPrivateKeyHeader)
            throw SemanticCheckException("[RSAPrivateKey::from_file] RSA private key header doesn't match the standard");

        // read all lines till the end and append to key_asn1_b64, except the footer
        std::getline(keyfile, line1);
        while (std::getline(keyfile, line2)) { // read next line and append the previous one
            key_asn1_b64 += line1;
            line1 = line2;
        }

        if (line1 != PKCS::Labels::encryptedPrivateKeyFooter)
            throw SemanticCheckException("[RSAPrivateKey::from_file] RSA private key footer doesn't match the standard");

        std::vector<uint8_t> key_asn1 = Base64::decode(key_asn1_b64);
        std::shared_ptr<ASN1Object> asn1_root = ASN1Parser::decode_all(std::move(key_asn1));
        struct AlgorithmIdentifier alg_id;

        if (int result = _EncryptedRSAPrivateKey_check(asn1_root, &alg_id); result != ERR_OK) {
            switch (result) {
                case ERR_SEMANTIC_CHECK_FAILED:
                    throw SemanticCheckException("[RSAPrivateKey::from_file] RSA private key semantic check failed");
                case ERR_FEATURE_UNSUPPORTED:
                    throw FeatureUnsupportedException("[RSAPrivateKey::from_file] RSA private key feature is unsupported");
                case ERR_ALGORITHM_UNSUPPORTED:
                    throw AlgorithmUnsupportedException("[RSAPrivateKey::from_file] RSA private key algorithm is unsupported");
                default:
                    throw std::runtime_error("[RSAPrivateKey::from_file] RSA private key unknown error");
            }
        }

        return _Decrypt_key(
            asn1_root->children()[1],
            &alg_id,
            std::move(passphrase)
        );
    }
}