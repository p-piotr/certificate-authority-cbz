#pragma once

#include <string>
#include <cstdint>
#include <vector>
#include <memory>
#include <unordered_map>
#include "include/asn1.h"

// Namespace containing PKCS-related operations
namespace CBZ::PKCS {

    using namespace ASN1;

    // Return values for functions operating on PKCS data
    #define ERR_OK 0
    #define ERR_ALGORITHM_UNSUPPORTED 1
    #define ERR_FEATURE_UNSUPPORTED 2
    #define ERR_SEMANTIC_CHECK_FAILED 3

    // Common OIDs found inside PKCS objects; this is not a complete list
    typedef std::string OID;
    struct AlgorithmIdentifier {
        uint32_t algorithm;
        std::shared_ptr<void> params;
    };

    namespace SupportedAlgorithms {

        namespace PrivateKeyAlgorithms {

            namespace RSAEncryption {
                extern const OID oid;

                // Parameters for this function should be NULL according to the PKCS
                // https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1
                int validate_parameters(std::shared_ptr<ASN1Object const> parameters_object);
            }

            enum PrivateKeyAlgorithmsEnum : uint32_t {
                rsaEncryption = 0x1
            };
            extern const std::unordered_map<OID, PrivateKeyAlgorithmsEnum> privateKeyAlgorithmsMap;
        }

        namespace EncryptionAlgorithms {

            namespace PBES2 {
                extern const OID oid;

                // https://www.rfc-editor.org/rfc/rfc8018.html#appendix-A.4
                struct Parameters {
                    struct AlgorithmIdentifier kdf;
                    struct AlgorithmIdentifier enc;
                };

                int extract_parameters(
                    std::shared_ptr<ASN1Object const> parameters_object,
                    struct Parameters *out_ptr
                );
            }

            enum EncryptionAlgorithmsEnum : uint32_t {
                pbes2 = 0x1001
            };
            extern const std::unordered_map<OID, EncryptionAlgorithmsEnum> encryptionAlgorithmsMap;
        }
        namespace KDFs {

            namespace PBKDF2 {
                extern const OID oid;

                // https://www.rfc-editor.org/rfc/rfc8018.html#appendix-A.2
                // 
                struct Parameters {
                    std::shared_ptr<std::vector<uint8_t>> salt;
                    uint32_t iterationCount;
                    uint32_t keyLength; // optional
                    struct AlgorithmIdentifier prf;
                };

                int extract_parameters(
                    std::shared_ptr<ASN1Object const> parameters_object,
                    struct Parameters *out_ptr
                );
            }

            enum KDFsEnum : uint32_t{
                pbkdf2 = 0x2001
            };
            extern const std::unordered_map<OID, KDFsEnum> kdfsMap;
        }

        namespace HMACFunctions {

            // This is a generic function for validating the HMACWithSHA* functions,
            // so there are no specific ones for each HMAC function declared
            int _generic_validate_parameters(std::shared_ptr<ASN1Object const> parameters_object);

            namespace HMACWithSHA1 {
                extern const OID oid;
            }

            namespace HMACWithSHA256 {
                extern const OID oid;
            }
            
            enum HMACFunctionsEnum : uint32_t {
                hmacWithSHA1 = 0x3001,
                hmacWithSHA256
            };
            extern const std::unordered_map<OID, HMACFunctionsEnum> hmacFunctionsMap;
        }

        namespace EncryptionSchemes {

            namespace AES_128_CBC {
                extern const OID oid;

                struct Parameters {
                    uint8_t iv[16];
                };

                int extract_parameters(
                    std::shared_ptr<ASN1Object const> parameters_object,
                    struct Parameters *out_ptr
                );
            }

            enum EncryptionSchemesEnum : uint32_t {
                aes_128_CBC = 0x4001
            };
            extern const std::unordered_map<OID, EncryptionSchemesEnum> encryptionSchemesMap;
        }
    }

    // Labels related to PKCS - headers/footers of PKCS-compatible files
    namespace Labels {
        extern const std::string privateKeyHeader;
        extern const std::string privateKeyFooter;
        extern const std::string encryptedPrivateKeyHeader;
        extern const std::string encryptedPrivateKeyFooter;
    }

    // Extracts the PKCS AlgorithmIdentifier structure found at @algorithm
    // If out_ptr != nullptr, extracted data is moved to the buffer. Otherwise,
    // only the semantic check is performed
    //
    // Input:
    // @algorithm - ASN1Object representing the PKCS AlgorithmIdentifier type (algorithm + parameters)
    // @out_ptr - optional pointer to the AlgorithmIdentifier structure
    int extract_algorithm(
        std::shared_ptr<ASN1Object const> algorithm,
        struct AlgorithmIdentifier *out_ptr
    );
}