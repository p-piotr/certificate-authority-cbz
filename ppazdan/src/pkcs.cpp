#include <string>
#include <cstdint>
#include <vector>
#include <memory>
#include <stdexcept>
#include <span>
#include "include/pkcs.h"
#include "include/asn1.h"
#include "include/kdf.hpp"
#include "include/aes.h"

namespace CBZ::PKCS {

    namespace SupportedAlgorithms {

        using namespace PrivateKeyAlgorithms;
        using namespace EncryptionAlgorithms;
        using namespace KDFs;
        using namespace HMACFunctions;
        using namespace EncryptionSchemes;

        const OID RSAEncryption::oid = "1.2.840.113549.1.1.1";
        const OID PBES2::oid = "1.2.840.113549.1.5.13";
        const OID PBKDF2::oid = "1.2.840.113549.1.5.12";
        const OID HMACWithSHA256::oid = "1.2.840.113549.2.9";
        const OID AES_128_CBC::oid = "2.16.840.1.101.3.4.1.2";

        const std::unordered_map<OID, PrivateKeyAlgorithmsEnum> PrivateKeyAlgorithms::privateKeyAlgorithmsMap = {
            { RSAEncryption::oid, PrivateKeyAlgorithmsEnum::rsaEncryption }
        };
        const std::unordered_map<OID, EncryptionAlgorithmsEnum> EncryptionAlgorithms::encryptionAlgorithmsMap = {
            { PBES2::oid, EncryptionAlgorithmsEnum::pbes2 }
        };
        const std::unordered_map<OID, KDFsEnum> KDFs::kdfsMap = {
            { PBKDF2::oid, KDFsEnum::pbkdf2 }
        };
        const std::unordered_map<OID, HMACFunctionsEnum> HMACFunctions::hmacFunctionsMap = {
            { HMACWithSHA256::oid, HMACFunctionsEnum::hmacWithSHA256 }
        };
        const std::unordered_map<OID, EncryptionSchemesEnum> EncryptionSchemes::encryptionSchemesMap = {
            { AES_128_CBC::oid, EncryptionSchemesEnum::aes_128_CBC }
        };

        int RSAEncryption::validate_parameters(
            std::shared_ptr<ASN1Object const> parameters_object
        ) {
            if (parameters_object->tag() != ASN1Tag::NULL_TYPE)
                return ERR_SEMANTIC_CHECK_FAILED;

            return ERR_OK;
        }

        int PBES2::extract_parameters(
            std::shared_ptr<ASN1Object const> parameters_object,
            struct Parameters *out_ptr
        ) {
            using namespace SupportedAlgorithms;

            if (parameters_object->tag() != ASN1Tag::SEQUENCE)
                return ERR_SEMANTIC_CHECK_FAILED;
            if (parameters_object->children().size() != 2)
                return ERR_SEMANTIC_CHECK_FAILED;

            auto kdf = parameters_object->children()[0],
                enc = parameters_object->children()[1];
            
            AlgorithmIdentifier kdf_ai, enc_ai;

            if (int result = KDFs::extract_algorithm(kdf, &kdf_ai); result != ERR_OK)
                return result;

            if (int result = EncryptionSchemes::extract_algorithm(enc, &enc_ai); result != ERR_OK)
                return result;

            if (out_ptr) {
                *out_ptr = Parameters{
                    kdf_ai,
                    enc_ai
                };
            }

            return ERR_OK;
        }

        int PBES2::decrypt_data(
            struct Parameters *params,
            std::shared_ptr<std::string> passphrase,
            std::span<uint8_t const> in,
            std::vector<uint8_t> &out
        ) {
            using namespace SupportedAlgorithms;

            size_t key_length;
            switch (params->enc.algorithm) {
                case EncryptionSchemes::aes_128_CBC:
                    key_length = 128;
                    break;
                default:
                    return ERR_ALGORITHM_UNSUPPORTED;
            }

            switch (params->kdf.algorithm) {
                case KDFs::pbkdf2: {

                }
            }
        }

        int PBKDF2::extract_parameters(
            std::shared_ptr<ASN1Object const> parameters_object,
            struct Parameters *out_ptr
        ) {
            if (parameters_object->tag() != ASN1Tag::SEQUENCE)
                return ERR_SEMANTIC_CHECK_FAILED;
            if (parameters_object->children().size() < 2)
                return ERR_SEMANTIC_CHECK_FAILED;

            std::shared_ptr<ASN1Object> salt;
            uint32_t iteration_count = 0, key_length = 0;
            AlgorithmIdentifier prf = {
                HMACFunctions::hmacWithSHA1,
                std::shared_ptr<void>(nullptr)
            };

            salt = parameters_object->children()[0];
            if (salt->tag() != ASN1Tag::OCTET_STRING)
                return ERR_SEMANTIC_CHECK_FAILED;

            mpz_class _iteration_count_mpz = std::static_pointer_cast<ASN1Integer>(parameters_object->children()[1])->value();
            if (_iteration_count_mpz > 0xFFFFFFFF) // This should never happen, but just in case
                return ERR_FEATURE_UNSUPPORTED;
            
            iteration_count = static_cast<uint32_t>(_iteration_count_mpz.get_ui());
            
            // Small bitmap to help with further field extraction
            // 1st LSB stands for the keyLength, while 2nd LSB stands for the prf
            uint8_t _bm = 0; 

            for (size_t i = 2; i < parameters_object->children().size(); i++) {
                auto next_field = parameters_object->children()[i];
                switch (next_field->tag()) {
                    case ASN1Tag::INTEGER: {
                        // Optional keyLength
                        if (_bm & 0x01 || _bm & 0x02)
                            // We either see the INTEGER for the second time, or already parsed the prf
                            // Either way, abort
                            return ERR_SEMANTIC_CHECK_FAILED;

                        mpz_class _key_length = std::static_pointer_cast<ASN1Integer>(parameters_object->children()[2])->value();
                        if (_key_length > 0xFFFFFFFF) // This also should never happen, but again, just in case
                            return ERR_FEATURE_UNSUPPORTED;
                        
                        key_length = _key_length.get_ui();
                        _bm |= 0x01;
                        break;
                    }
                    case ASN1Tag::SEQUENCE: {
                        // prf
                        if (_bm & 0x02)
                            // We've already been there; abort
                            return ERR_SEMANTIC_CHECK_FAILED;

                        // Try to extract the algorithm
                        AlgorithmIdentifier _prf;
                        if (int result = SupportedAlgorithms::extract_algorithm(next_field, &_prf); result != 0)
                            return result;

                        prf = _prf;
                        _bm |= 0x02;
                        break;
                    }
                    default:
                        return ERR_SEMANTIC_CHECK_FAILED;
                }
            }
            
            // Finish up; copy data if needed and return
            if (out_ptr) {
                *out_ptr = PBKDF2::Parameters{
                    std::make_shared<std::vector<uint8_t>>(salt->value()),
                    iteration_count,
                    key_length,
                    prf
                };
            }

            return ERR_OK;
        }

        int PBKDF2::derive_key(
            struct Parameters *params,
            std::shared_ptr<std::string> passphrase,
            size_t key_length,
            std::vector<uint8_t> &out_key
        ) {
            switch (params->prf.algorithm) {
                case HMACFunctions::hmacWithSHA1: {
                    out_key.resize(key_length);
                    CBZ::KDF::PBKDF2<HMAC<SHA::SHA1>>::derive_key(
                        std::span{reinterpret_cast<uint8_t*>(passphrase->data()), passphrase->size()},
                        std::span{*params->salt},
                        params->iterationCount,
                        key_length,
                        out_key.data()
                    );
                    return ERR_OK;
                }
                case HMACFunctions::hmacWithSHA256: {
                    out_key.resize(key_length);
                    CBZ::KDF::PBKDF2<HMAC<SHA::SHA256>>::derive_key(
                        std::span{reinterpret_cast<uint8_t*>(passphrase->data()), passphrase->size()},
                        std::span{*params->salt},
                        params->iterationCount,
                        key_length,
                        out_key.data()
                    );
                    return ERR_OK;
                }
                default:
                    return ERR_ALGORITHM_UNSUPPORTED;
            }
        }

        int HMACFunctions::_generic_validate_parameters(
            std::shared_ptr<ASN1Object const> parameters_object
        ) {
            if (parameters_object->tag() != ASN1Tag::NULL_TYPE)
                return ERR_SEMANTIC_CHECK_FAILED;

            return ERR_OK;
        }

        int AES_128_CBC::extract_parameters(
            std::shared_ptr<ASN1Object const> parameters_object,
            struct Parameters *out_ptr
        ) {
            constexpr const size_t IV_SIZE = 16;

            if (parameters_object->tag() != ASN1Tag::OCTET_STRING)
                return ERR_SEMANTIC_CHECK_FAILED;
            if (parameters_object->value().size() != IV_SIZE)
                return ERR_SEMANTIC_CHECK_FAILED;
            
            if (out_ptr != nullptr) {
                std::memcpy(
                    out_ptr->iv,
                    parameters_object->value().data(),
                    IV_SIZE
                );
            } 
            return ERR_OK;
        }

        int PrivateKeyAlgorithms::extract_algorithm(
            std::shared_ptr<ASN1Object const> algorithm,
            struct AlgorithmIdentifier *out_ptr,
            std::string const &oid
        ) {
            if (algorithm->children().size() != 2)
                return ERR_SEMANTIC_CHECK_FAILED;

            const std::string algorithm_oid = (oid.empty()) ? 
                std::static_pointer_cast<ASN1ObjectIdentifier const>(algorithm->children()[0])->value() : oid;
            auto parameters = algorithm->children()[1];

            // PrivateKeyAlgorithms
            if (
                auto search = SupportedAlgorithms::PrivateKeyAlgorithms::privateKeyAlgorithmsMap.find(algorithm_oid);
                search != SupportedAlgorithms::PrivateKeyAlgorithms::privateKeyAlgorithmsMap.end()
            ) {
                using namespace SupportedAlgorithms::PrivateKeyAlgorithms;
                switch (search->second) {
                    case rsaEncryption: {
                        if (int result = RSAEncryption::validate_parameters(parameters); result != ERR_OK)
                            return result;

                        if (out_ptr) {
                            *out_ptr = AlgorithmIdentifier{
                                rsaEncryption,
                                std::shared_ptr<void>(nullptr)
                            };
                        }
                        return ERR_OK;
                    }
                    default:
                        throw std::runtime_error("[PKCS::PrivateKeyAlgorithms::extract_algorithm] Matched something in the map, but not exactly... call the cops should you see this");
                }
            }

            return ERR_ALGORITHM_UNSUPPORTED;
        }

        int EncryptionAlgorithms::extract_algorithm(
            std::shared_ptr<ASN1Object const> algorithm,
            struct AlgorithmIdentifier *out_ptr,
            std::string const &oid
        ) {
            if (algorithm->children().size() != 2)
                return ERR_SEMANTIC_CHECK_FAILED;

            const std::string algorithm_oid = (oid.empty()) ? 
                std::static_pointer_cast<ASN1ObjectIdentifier const>(algorithm->children()[0])->value() : oid;
            auto parameters = algorithm->children()[1];

            // EncryptionAlgorithms
            if (
                auto search = SupportedAlgorithms::EncryptionAlgorithms::encryptionAlgorithmsMap.find(algorithm_oid);
                search != SupportedAlgorithms::EncryptionAlgorithms::encryptionAlgorithmsMap.end()
            ) {
                using namespace SupportedAlgorithms::EncryptionAlgorithms;
                switch (search->second) {
                    case pbes2: {
                        auto pbes2_parameters = out_ptr ? 
                            std::make_shared<PBES2::Parameters>() : std::shared_ptr<PBES2::Parameters>(nullptr);
                        if (int result = PBES2::extract_parameters(parameters, pbes2_parameters.get()); result != ERR_OK)
                            return result;

                        if (out_ptr) {
                            *out_ptr = AlgorithmIdentifier{
                                pbes2,
                                pbes2_parameters
                            };
                        }
                        return ERR_OK;
                    }
                    default:
                        throw std::runtime_error("[PKCS::EncryptionAlgorithms::extract_algorithm] Matched something in the map, but not exactly... call the cops should you see this");
                }
            }

            return ERR_ALGORITHM_UNSUPPORTED;
        }

        int KDFs::extract_algorithm(
            std::shared_ptr<ASN1Object const> algorithm,
            struct AlgorithmIdentifier *out_ptr,
            std::string const &oid
        ) {
            if (algorithm->children().size() != 2)
                return ERR_SEMANTIC_CHECK_FAILED;

            const std::string algorithm_oid = (oid.empty()) ? 
                std::static_pointer_cast<ASN1ObjectIdentifier const>(algorithm->children()[0])->value() : oid;
            auto parameters = algorithm->children()[1];

            // KDFs
            if (
                auto search = SupportedAlgorithms::KDFs::kdfsMap.find(algorithm_oid);
                search != SupportedAlgorithms::KDFs::kdfsMap.end()
            ) {
                using namespace SupportedAlgorithms::KDFs;
                switch (search->second) {
                    case pbkdf2: {
                        auto pbkdf2_parameters = out_ptr ?
                            std::make_shared<PBKDF2::Parameters>() : std::shared_ptr<PBKDF2::Parameters>(nullptr);
                        if (int result = PBKDF2::extract_parameters(parameters, pbkdf2_parameters.get()); result != ERR_OK)
                            return result;
                        
                        if (out_ptr) {
                            *out_ptr = AlgorithmIdentifier{
                                pbkdf2,
                                pbkdf2_parameters
                            };
                        }
                        return ERR_OK;
                    }
                    default:
                        throw std::runtime_error("[PKCS::KDFs::extract_algorithm] Matched something in the map, but not exactly... call the cops should you see this");
                }
            }

            return ERR_ALGORITHM_UNSUPPORTED;
        }

        int HMACFunctions::extract_algorithm(
            std::shared_ptr<ASN1Object const> algorithm,
            struct AlgorithmIdentifier *out_ptr,
            std::string const &oid
        ) {
            if (algorithm->children().size() != 2)
                return ERR_SEMANTIC_CHECK_FAILED;

            const std::string algorithm_oid = (oid.empty()) ? 
                std::static_pointer_cast<ASN1ObjectIdentifier const>(algorithm->children()[0])->value() : oid;
            auto parameters = algorithm->children()[1];

            // HMACFunctions
            if (
                auto search = SupportedAlgorithms::HMACFunctions::hmacFunctionsMap.find(algorithm_oid);
                search != SupportedAlgorithms::HMACFunctions::hmacFunctionsMap.end()
            ) {
                using namespace SupportedAlgorithms::HMACFunctions;
                switch (search->second) {
                    case hmacWithSHA1:
                    case hmacWithSHA256: {
                        if (int result = _generic_validate_parameters(parameters); result != ERR_OK)
                            return result;

                        if (out_ptr) {
                            *out_ptr = AlgorithmIdentifier{
                                search->second,
                                std::shared_ptr<void>(nullptr)
                            };
                        }
                        return ERR_OK;
                    }
                    default:
                        throw std::runtime_error("[PKCS::HMACFunctions::extract_algorithm] Matched something in the map, but not exactly... call the cops should you see this");
                }
            }

            return ERR_ALGORITHM_UNSUPPORTED;
        }

        int EncryptionSchemes::extract_algorithm(
            std::shared_ptr<ASN1Object const> algorithm,
            struct AlgorithmIdentifier *out_ptr,
            std::string const &oid
        ) {
            if (algorithm->children().size() != 2)
                return ERR_SEMANTIC_CHECK_FAILED;

            const std::string algorithm_oid = (oid.empty()) ? 
                std::static_pointer_cast<ASN1ObjectIdentifier const>(algorithm->children()[0])->value() : oid;
            auto parameters = algorithm->children()[1];

            // EncryptionSchemes
            if (
                auto search = SupportedAlgorithms::EncryptionSchemes::encryptionSchemesMap.find(algorithm_oid);
                search != SupportedAlgorithms::EncryptionSchemes::encryptionSchemesMap.end()
            ) {
                using namespace SupportedAlgorithms::EncryptionSchemes;
                switch (search->second) {
                    case aes_128_CBC: {
                        auto aes_parameters = out_ptr ?
                            std::make_shared<AES_128_CBC::Parameters>() : std::shared_ptr<AES_128_CBC::Parameters>(nullptr);
                        if (int result = AES_128_CBC::extract_parameters(parameters, aes_parameters.get()); result != ERR_OK)
                            return result;
                        
                        if (out_ptr) {
                            *out_ptr = AlgorithmIdentifier{
                                aes_128_CBC,
                                aes_parameters
                            };
                        }
                        return ERR_OK;
                    }
                    default:
                        throw std::runtime_error("[PKCS::EncryptionSchemes::extract_algorithm] Matched something in the map, but not exactly... call the cops should you see this");
                }
            }

            return ERR_ALGORITHM_UNSUPPORTED;
        }
    }

    namespace Labels {
        const std::string privateKeyHeader = "-----BEGIN PRIVATE KEY-----";
        const std::string privateKeyFooter = "-----END PRIVATE KEY-----";
        const std::string encryptedPrivateKeyHeader = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
        const std::string encryptedPrivateKeyFooter = "-----END ENCRYPTED PRIVATE KEY-----";
    }

    int SupportedAlgorithms::extract_algorithm(
        std::shared_ptr<ASN1Object const> algorithm,
        struct AlgorithmIdentifier *out_ptr
    ) {
        if (algorithm->children().size() != 2)
            return ERR_SEMANTIC_CHECK_FAILED;

        auto algorithm_oid = std::static_pointer_cast<ASN1ObjectIdentifier const>(algorithm->children()[0])->value();
        auto parameters = algorithm->children()[1];

        // Iterate through all supported algorithm categories

        int result;
        result = PrivateKeyAlgorithms::extract_algorithm(algorithm, out_ptr, algorithm_oid);
        if (result != ERR_ALGORITHM_UNSUPPORTED) // If algorithm was supported, we could succeed or fail; either way return
            return result;
        
        result = EncryptionAlgorithms::extract_algorithm(algorithm, out_ptr, algorithm_oid);
        if (result != ERR_ALGORITHM_UNSUPPORTED)
            return result;

        result = KDFs::extract_algorithm(algorithm, out_ptr, algorithm_oid);
        if (result != ERR_ALGORITHM_UNSUPPORTED)
            return result;

        result = HMACFunctions::extract_algorithm(algorithm ,out_ptr, algorithm_oid);
        if (result != ERR_ALGORITHM_UNSUPPORTED)
            return result;

        result = EncryptionSchemes::extract_algorithm(algorithm, out_ptr, algorithm_oid);
        if (result != ERR_ALGORITHM_UNSUPPORTED)
            return result;

        return ERR_ALGORITHM_UNSUPPORTED;
    }
}