#include <iostream>
#include <cstdint>
#include <cstddef>
#include <vector>
#include <fstream>
#include <sstream>
#include <span>
#include <gmpxx.h>
#include "pkcs/private_key.h"
#include "asn1/asn1.h"
#include "utils/base64.h"
#include "pkcs/pkcs.h"
#include "utils/security.hpp"
#include "utils/io.h"

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
    int _RSAPrivateKey_check_and_expand(ASN1Object& root_object) {
        using namespace PrivateKeySupportedAlgorithms;

        // Root object should contain 3 or 4 children (attributies field is optional)
        if (
            root_object.tag() != ASN1Tag::SEQUENCE
            || root_object.children().size() < 3
            || root_object.children().size() > 4
        )
            return ERR_SEMANTIC_CHECK_FAILED;

        const ASN1Object& version = root_object.children()[0];
        const ASN1Object& private_key_algorithm = root_object.children()[1];
        ASN1Object& private_key = root_object._children[2];

        if (version.tag() != ASN1Tag::INTEGER) { // 'version' must be of type INTEGER
            return ERR_SEMANTIC_CHECK_FAILED;
        }
        if (static_cast<const ASN1Integer&>(version).value() != 0) { // 'version' must be equal to 0
            return ERR_FEATURE_UNSUPPORTED;
        }
        if (private_key_algorithm.tag() != ASN1Tag::SEQUENCE) { // 'private_key_algorithm' must be of type SEQUENCE
            return ERR_SEMANTIC_CHECK_FAILED;
        }
        if (private_key.tag() != ASN1Tag::OCTET_STRING) { // 'private_key' must be of type OCTET_STRING
            return ERR_SEMANTIC_CHECK_FAILED;
        }

        // Now proceed to the algorithm extraction
        struct AlgorithmIdentifier alg_id;
        if (
            int result = PrivateKeyAlgorithms::extract_algorithm(private_key_algorithm, &alg_id);
            result != 0
        ) {
            return result;
        }
        
        // Iterate through supported algorithms and act accordingly
        switch (alg_id.algorithm) {
            case PrivateKeyAlgorithms::rsaEncryption: {
                // According to the rsaEncryption PKCS specification, the private_key OCTET STRING
                // is actually a SEQUENCE containing 9 INTEGERs
                if (private_key.children().size() == 0) {
                    // Decode the private_key according to the PKCS#1 structure, since
                    // the ASN.1 parser didn't do it (it's a Primitive OCTET STRING after all)
                    ASN1Object pk_sequence = ASN1Parser::decode_all(std::move(private_key.value()));
                    if (pk_sequence.children().size() != 9)
                        return ERR_SEMANTIC_CHECK_FAILED;

                    private_key._children.push_back(pk_sequence);
                } else if (private_key.children()[0].children().size() != 9)
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
        const ASN1Object& root_object,
        struct AlgorithmIdentifier* out_ptr
    ) {
        using namespace PrivateKeySupportedAlgorithms;

        if (root_object.tag() != ASN1Tag::SEQUENCE || root_object.children().size() != 2) {
            return ERR_SEMANTIC_CHECK_FAILED;
        }
        
        auto encryption_algorithm = root_object.children()[0];
        auto encrypted_data = root_object.children()[1];
        
        if (int result = EncryptionAlgorithms::extract_algorithm(encryption_algorithm, out_ptr); result != ERR_OK) {
            return result;
        }
        if (encrypted_data.tag() != ASN1Tag::OCTET_STRING) {
            return ERR_SEMANTIC_CHECK_FAILED;
        }

        return ERR_OK;
    }

    RSAPrivateKey _Decrypt_key(
        const ASN1Object& encrypted_data,
        const struct AlgorithmIdentifier* alg_id,
        std::string&& passphrase
    ) {
        using namespace PrivateKeySupportedAlgorithms;

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
                        std::span{encrypted_data.value()},
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
    void RSAPrivateKey::print() const {
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

    RSAPrivateKey _Decode_key(ASN1Object& asn1_root) {
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
        auto pk_sequence = asn1_root.children()[2].children()[0];
        std::vector<mpz_class> rsa_params(9);
        // iterate through all 9 integers and save them
        for (size_t i = 0; i < 9; i++) {
            auto integer_obj = static_cast<const ASN1::ASN1Integer&>(pk_sequence.children()[i]);
            rsa_params[i] = integer_obj.value();
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

    // Compares header at the beginning of given Base64 buffer
    // with another specified header
    bool _compare_header(const std::string& b64, const std::string& h) {
        if (b64.size() < h.size())
            return false;

        int r = std::memcmp(
            b64.data(),
            h.data(),
            h.size()
        );

        if (r == 0)
            return true;
        else return false;
    }

    // Compares footer at the end of given Base64 buffer
    // with another specifier footer
    bool _compare_footer(const std::string& b64, const std::string& f) {
        if (b64.size() < f.size())
            return false;

        int r = std::memcmp(
            b64.data() + (b64.size() - f.size()),
            f.data(),
            f.size()
        );

        if (r == 0)
            return true;
        else return false;
    }

    RSAPrivateKey RSAPrivateKey::from_base64_buffer(std::string&& key_b64) {
        int h_c = _compare_header(key_b64, Labels::privateKeyHeader);
        int f_c = _compare_footer(key_b64, Labels::privateKeyFooter);
        if (!h_c || !f_c) {
            // header/footer doesn't match
            // check whether given key is encrypted and if it is, handle appropriately
            // otherwise throw
            h_c = _compare_header(key_b64, Labels::encryptedPrivateKeyHeader);
            f_c = _compare_footer(key_b64, Labels::encryptedPrivateKeyFooter);
            if (!h_c || !f_c) {
                CBZ::Security::secure_zero_memory(key_b64);
                throw std::runtime_error("[RSAPrivateKey::from_base64_buffer] RSA private key header/footer does not match the standard");
            }

            // the key is encrypted
            std::string passphrase = CBZ::Utils::IO::ask_for_password();
            return from_base64_buffer_with_passphrase(std::move(key_b64), std::move(passphrase));
        }

        std::span<char> key_asn1_b64 = std::span{
            key_b64.data() + Labels::privateKeyHeader.size(),
            key_b64.size() - (Labels::privateKeyHeader.size() + Labels::privateKeyFooter.size())
        };
        std::vector<uint8_t> key_asn1 = Base64::decode(key_asn1_b64);
        ASN1Object asn1_root = ASN1Object::decode(key_asn1);

        // zero the base64 and asn1 buffers
        CBZ::Security::secure_zero_memory(key_b64);
        CBZ::Security::secure_zero_memory(key_asn1);

        // decode the final expanded structure into 9 integers
        return _Decode_key(asn1_root);
    }

    // Loads a private key from file
    // This variant may only parse unencryptd keys
    //
    // Input:
    // @filepath - path to the file containing the private key in PKCS#8
    RSAPrivateKey RSAPrivateKey::from_file(const std::string& filepath) {
        std::string key_b64;
        size_t keyfile_size = CBZ::Utils::get_file_size(filepath.c_str());
        key_b64.resize(keyfile_size);

        try {
            CBZ::Security::secure_read_file(
                filepath.c_str(),
                std::as_writable_bytes(std::span{key_b64})
            );
        } catch (const std::exception &e) {
            std::throw_with_nested(std::runtime_error("[RSAPrivateKey::from_file] Could not read RSA private key from file"));
        }

        return from_base64_buffer(std::move(key_b64));
    }

    RSAPrivateKey RSAPrivateKey::from_base64_buffer_with_passphrase(std::string&& key_b64, std::string&& passphrase) {
        int h_c = _compare_header(key_b64, Labels::encryptedPrivateKeyHeader);
        int f_c = _compare_footer(key_b64, Labels::encryptedPrivateKeyFooter);
        if (!h_c || !f_c) {
            // header/footer doesn't match
            // check whether given key is unencrypted and if it is, handle appropriately
            // otherwise throw
            h_c = _compare_header(key_b64, Labels::privateKeyHeader);
            f_c = _compare_footer(key_b64, Labels::privateKeyFooter);
            if (!h_c || !f_c) {
                CBZ::Security::secure_zero_memory(key_b64);
                CBZ::Security::secure_zero_memory(passphrase);
                throw std::runtime_error("[RSAPrivateKey::from_file] RSA private key header/footer does not match the standard");
            }

            // the key is unencrypted
            CBZ::Security::secure_zero_memory(passphrase);
            return from_base64_buffer(std::move(key_b64));
        }

        std::span<char> key_asn1_b64 = std::span{
            key_b64.data() + Labels::encryptedPrivateKeyHeader.size(),
            key_b64.size() - (Labels::encryptedPrivateKeyHeader.size() + Labels::encryptedPrivateKeyFooter.size())
        };
        std::vector<uint8_t> key_asn1 = Base64::decode(key_asn1_b64);
        ASN1Object asn1_root = ASN1Object::decode(key_asn1);
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

        // zero the base64 and asn1 buffers
        // alg_id will get deleted by itself so it won't leak anything
        CBZ::Security::secure_zero_memory(key_b64);
        CBZ::Security::secure_zero_memory(key_asn1);

        return _Decrypt_key(
            asn1_root.children()[1],
            &alg_id,
            std::move(passphrase)
        );
    }
    
    RSAPrivateKey RSAPrivateKey::from_file_with_passphrase(const std::string& filepath, std::string&& passphrase) {
        std::string key_b64;
        size_t keyfile_size = CBZ::Utils::get_file_size(filepath.c_str());
        key_b64.resize(keyfile_size);

        try {
            CBZ::Security::secure_read_file(
                filepath.c_str(),
                std::as_writable_bytes(std::span{key_b64})
            );
        } catch (const std::exception &e) {
            std::throw_with_nested(std::runtime_error("[RSAPrivateKey::from_file] Could not read RSA private key from file"));
        }

        return from_base64_buffer_with_passphrase(std::move(key_b64), std::move(passphrase));
    }
}
