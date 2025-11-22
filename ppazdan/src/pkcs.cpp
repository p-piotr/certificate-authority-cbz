#include <string>
#include <cstdint>
#include <vector>
#include <memory>
#include <stdexcept>
#include "include/pkcs.h"
#include "include/asn1.h"

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

        const std::unordered_map<OID, PrivateKeyAlgorithmsEnum> privateKeyAlgorithmsMap = {
            { RSAEncryption::oid, PrivateKeyAlgorithmsEnum::rsaEncryption }
        };
        const std::unordered_map<OID, EncryptionAlgorithmsEnum> encryptionAlgorithmsMap = {
            { PBES2::oid, EncryptionAlgorithmsEnum::pbes2 }
        };
        const std::unordered_map<OID, KDFsEnum> kdfsMap = {
            { PBKDF2::oid, KDFsEnum::pbkdf2 }
        };
        const std::unordered_map<OID, HMACFunctionsEnum> hmacFunctionsMap = {
            { HMACWithSHA256::oid, HMACFunctionsEnum::hmacWithSHA256 }
        };
        const std::unordered_map<OID, EncryptionSchemesEnum> encryptionSchemesMap = {
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
            using namespace PKCS::SupportedAlgorithms;

            if (parameters_object->children().size() != 2)
                return ERR_SEMANTIC_CHECK_FAILED;

            auto kdf = parameters_object->children()[0],
                enc = parameters_object->children()[1];
            
            if (kdf->children().size() != 2)
                return false;
            if (enc->children().size() != 2)
                return false;

            auto kdf_oi = std::static_pointer_cast<ASN1ObjectIdentifier>(kdf->children()[0]);
            auto kdf_params = kdf->children()[1];

            auto search = KDFs::kdfsMap.find(kdf_oi->value());
            if (search == KDFs::kdfsMap.end())
                return ERR_ALGORITHM_UNSUPPORTED;

            auto kdf_algorithm = search->second;
            // TODO: finish
        }

        int PBKDF2::extract_parameters(
            std::shared_ptr<ASN1Object const> parameters_object,
            struct Parameters *out_ptr
        ) {

        }

        int HMACWithSHA256::validate_parameters(
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
    }

    namespace Labels {
        const std::string privateKeyHeader = "-----BEGIN PRIVATE KEY-----";
        const std::string privateKeyFooter = "-----END PRIVATE KEY-----";
        const std::string encryptedPrivateKeyHeader = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
        const std::string encryptedPrivateKeyFooter = "-----END ENCRYPTED PRIVATE KEY-----";
    }

    int extract_algorithm(
        std::shared_ptr<ASN1Object const> algorithm,
        struct AlgorithmIdentifier *out_ptr
    ) {
        if (algorithm->children().size() != 2)
            return ERR_SEMANTIC_CHECK_FAILED;

        auto algorithm_oid = std::static_pointer_cast<ASN1ObjectIdentifier const>(algorithm->children()[0])->value();
        auto parameters = algorithm->children()[1];

        // Iterate through all supported algorithm categories

        // PrivateKeyAlgorithms
        if (
            auto search = SupportedAlgorithms::PrivateKeyAlgorithms::privateKeyAlgorithmsMap.find(algorithm_oid);
            search != SupportedAlgorithms::PrivateKeyAlgorithms::privateKeyAlgorithmsMap.end()
        ) {
            using namespace SupportedAlgorithms::PrivateKeyAlgorithms;
            switch (search->second) {
                case rsaEncryption: {
                    int result = RSAEncryption::validate_parameters(parameters);
                    if (result != ERR_OK)
                        return result;

                    if (out_ptr) {
                        out_ptr->algorithm = rsaEncryption;
                        out_ptr->params = std::make_shared<void>(nullptr);
                    }
                    return ERR_OK;
                }
                default: {
                    // call the cops
                    throw std::runtime_error("[PKCS::extract_algorithm] Matched something in the map, but not exactly... call the cops should you see this");
                }
            }
        }

        // EncryptionAlgorithms
        if (
            auto search = SupportedAlgorithms::EncryptionAlgorithms::encryptionAlgorithmsMap.find(algorithm_oid);
            search != SupportedAlgorithms::EncryptionAlgorithms::encryptionAlgorithmsMap.end()
        ) {

        }

        // KDFs
        if (
            auto search = SupportedAlgorithms::KDFs::kdfsMap.find(algorithm_oid);
            search != SupportedAlgorithms::KDFs::kdfsMap.end()
        ) {

        }

        // HMACFunctions
        if (
            auto search = SupportedAlgorithms::HMACFunctions::hmacFunctionsMap.find(algorithm_oid);
            search != SupportedAlgorithms::HMACFunctions::hmacFunctionsMap.end()
        ) {

        }

        // EncryptionSchemes
        if (
            auto search = SupportedAlgorithms::EncryptionSchemes::encryptionSchemesMap.find(algorithm_oid);
            search != SupportedAlgorithms::EncryptionSchemes::encryptionSchemesMap.end()
        ) {

        }

        return ERR_ALGORITHM_UNSUPPORTED;
    }
}