#pragma once

#include <string>
#include <cstdint>
#include <vector>
#include <memory>
#include <span>
#include <unordered_map>
#include <variant>
#include <utility>
#include "asn1/asn1.h"

// Namespace containing PKCS-related operations
namespace CBZ::PKCS {

    using namespace CBZ::ASN1;

    // Return values for functions operating on PKCS data
    #define ERR_OK 0
    #define ERR_ALGORITHM_UNSUPPORTED 1
    #define ERR_FEATURE_UNSUPPORTED 2
    #define ERR_SEMANTIC_CHECK_FAILED 3

    typedef std::string OID;
    struct AlgorithmIdentifier {
        uint32_t algorithm;
        std::shared_ptr<void> params;

        AlgorithmIdentifier() : algorithm(0), params(std::shared_ptr<void>(nullptr)) {}

        AlgorithmIdentifier(
            uint32_t algorithm_,
            std::shared_ptr<void> params_ = std::shared_ptr<void>(nullptr)
        )
            : algorithm(algorithm_), params(params_) {}

        ~AlgorithmIdentifier() {
            algorithm = 0;
            // params will get destroyed by themselves since it's a shared_ptr
        }

        // Those functions only exists for MaksymilianOliwaCode™ compatibility reasons
        // They don't take into consideration any parameters, always return a NULL_TYPE
        // Also, they only check the CSRSupportedAlgorithms for a matching OID
        //
        // Shouldn't be used except a carefully created legacy sandbox where MaksymilianOliwaCode wants to use them
        ASN1Object to_asn1() const;
        std::vector<uint8_t> encode() const;

        friend std::ostream& operator<<(std::ostream& os, const PKCS::AlgorithmIdentifier& ai);
    };

    namespace PrivateKeySupportedAlgorithms {

        // Extracts the PKCS AlgorithmIdentifier structure found at @algorithm
        // If out_ptr != nullptr, extracted data is moved to the buffer. Otherwise,
        // only the semantic check is performed
        //
        // Input:
        // @algorithm - ASN1Object representing the PKCS AlgorithmIdentifier type (algorithm + parameters)
        // @out_ptr - optional pointer to the AlgorithmIdentifier structure
        int extract_algorithm(
            const ASN1Object& algorithm,
            struct AlgorithmIdentifier* out_ptr
        );

        namespace PrivateKeyAlgorithms {

            int extract_algorithm(
                const ASN1Object& algorithm,
                struct AlgorithmIdentifier* out_ptr,
                const std::string& oid = ""
            );

            namespace RSAEncryption {
                extern const OID oid;

                // Parameters for this function should be NULL according to the PKCS
                // https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1
                int validate_parameters(const ASN1Object& parameters_object);
            }

            enum PrivateKeyAlgorithmsEnum : uint32_t {
                rsaEncryption = 0x1
            };
            extern const std::unordered_map<OID, PrivateKeyAlgorithmsEnum> privateKeyAlgorithmsMap;
        }

        namespace EncryptionAlgorithms {

            int extract_algorithm(
                const ASN1Object& algorithm,
                struct AlgorithmIdentifier* out_ptr,
                const std::string& oid = ""
            );

            namespace PBES2 {
                extern const OID oid;

                // https://www.rfc-editor.org/rfc/rfc8018.html#appendix-A.4
                struct Parameters {
                    struct AlgorithmIdentifier kdf;
                    struct AlgorithmIdentifier enc;
                };

                int extract_parameters(
                    const ASN1Object& parameters_object,
                    struct Parameters* out_ptr
                );

                // Decrypts data using given passphrase, according
                // to the KDF and encryption scheme specified in parameters
                //
                // Input:
                // @params - Parameters struct specifying underlying algorithms
                // @passphrase - passphrase to be used with the KDF, passed as an rvalue
                //               (contents of the passphrase will be securely deleted afterwards)
                // @in - buffer with encrypted data
                // @out - vector to store decrypted data
                int decrypt_data(
                    struct Parameters* params,
                    std::shared_ptr<const std::string> passphrase,
                    std::span<const uint8_t> in,
                    std::vector<uint8_t>& out
                );
            }

            enum EncryptionAlgorithmsEnum : uint32_t {
                pbes2 = 0x1001
            };
            extern const std::unordered_map<OID, EncryptionAlgorithmsEnum> encryptionAlgorithmsMap;
        }
        namespace KDFs {

            int extract_algorithm(
                const ASN1Object& algorithm,
                struct AlgorithmIdentifier* out_ptr,
                const std::string& oid = ""
            );

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
                    const ASN1Object& parameters_object,
                    struct Parameters* out_ptr
                );

                // Derive key according to given KDF parameters structure
                // and a passphrase
                //
                // Input:
                // @params - pointer to the Parameters structure, storing KDF options
                // @passphrase - passphrase to derive key from passed as an rvalue
                //               this value will be securely deleted when deriving process
                //               completes
                // @key_length - desired key length, in bytes
                // @out_key - reference to a vector storing the output key
                int derive_key(
                    struct Parameters* params,
                    std::shared_ptr<std::string const> passphrase,
                    size_t key_length,
                    std::vector<uint8_t>& out_key
                );
            }

            enum KDFsEnum : uint32_t{
                pbkdf2 = 0x2001
            };
            extern const std::unordered_map<OID, KDFsEnum> kdfsMap;
        }

        namespace HMACFunctions {

            int extract_algorithm(
                const ASN1Object& algorithm,
                struct AlgorithmIdentifier* out_ptr,
                const std::string& oid = ""
            );

            // This is a generic function for validating the HMACWithSHA* functions,
            // so there are no specific ones for each HMAC function declared
            int _generic_validate_parameters(const ASN1Object& parameters_object);

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

            int extract_algorithm(
                const ASN1Object& algorithm,
                struct AlgorithmIdentifier* out_ptr,
                const std::string& oid = ""
            );

            namespace AES {
                struct Parameters {
                    uint8_t iv[16];
                };

                int extract_parameters(
                    const ASN1Object& parameters_object,
                    struct Parameters* out_ptr
                );

                namespace AES_128_CBC {
                    extern const OID oid;
                }
                namespace AES_256_CBC {
                    extern const OID oid;
                }
            }

            enum EncryptionSchemesEnum : uint32_t {
                aes_128_CBC = 0x4001,
                aes_256_CBC
            };
            extern const std::unordered_map<OID, EncryptionSchemesEnum> encryptionSchemesMap;
        }
    }

    // unordered map that maps given OID to it's correspoing string type
    // I just based this on what openssl uses, but here's more offical documentation
    // https://www.itu.int/rec/T-REC-X.520-201910-I/en
    // https://datatracker.ietf.org/doc/html/rfc2985
    extern const std::unordered_map<std::string, ASN1Tag> attributeStringTypeMap;
}
