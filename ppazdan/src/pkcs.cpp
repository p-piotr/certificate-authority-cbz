#include <string>
#include <cstdint>
#include <vector>
#include <memory>
#include <stdexcept>
#include "include/pkcs.h"
#include "include/asn1.h"

namespace CBZ::PKCS {

    namespace SupportedAlgorithms {

        namespace OIDs {
            const OID PrivateKeyAlgorithms::rsaEncryption = "1.2.840.113549.1.1.1";
            const OID EncryptionAlgorithms::pkcs5PBES2 = "1.2.840.113549.1.5.13";
            const OID KDFs::pkcs5PBKDF2 = "1.2.840.113549.1.5.12";
            const OID HMACFunctions::hmacWithSHA256 = "1.2.840.113549.2.9";
            const OID EncryptionSchemes::aes128_CBC = "2.16.840.1.101.3.4.1.2";
        }

        namespace Maps {
            const std::unordered_map<OID, Enums::PrivateKeyAlgorithms> privateKeyAlgorithmsMap = {
                { OIDs::PrivateKeyAlgorithms::rsaEncryption, Enums::PrivateKeyAlgorithms::rsaEncryption }
            };
            const std::unordered_map<OID, Enums::EncryptionAlgorithms> encryptionAlgorithmsMap = {
                { OIDs::EncryptionAlgorithms::pkcs5PBES2, Enums::EncryptionAlgorithms::pkcs5PBES2 }
            };
            const std::unordered_map<OID, Enums::KDFs> kdfsMap = {
                { OIDs::KDFs::pkcs5PBKDF2, Enums::KDFs::pkcs5PBKDF2 }
            };
            const std::unordered_map<OID, Enums::HMACFunctions> hmacFunctionsMap = {
                { OIDs::HMACFunctions::hmacWithSHA256, Enums::HMACFunctions::hmacWithSHA256 }
            };
            const std::unordered_map<OID, Enums::EncryptionSchemes> encryptionSchemesMap = {
                { OIDs::EncryptionSchemes::aes128_CBC, Enums::EncryptionSchemes::aes128_CBC }
            };
        }
    }

    namespace Labels {
        const std::string privateKeyHeader = "-----BEGIN PRIVATE KEY-----";
        const std::string privateKeyFooter = "-----END PRIVATE KEY-----";
        const std::string encryptedPrivateKeyHeader = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
        const std::string encryptedPrivateKeyFooter = "-----END ENCRYPTED PRIVATE KEY-----";
    }
}