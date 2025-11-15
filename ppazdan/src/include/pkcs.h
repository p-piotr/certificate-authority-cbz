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

    // Common OIDs found inside PKCS objects; this is not a complete list
    typedef std::string OID;
    namespace SupportedAlgorithms {
        namespace OIDs {
            namespace PrivateKeyAlgorithms {
                extern const OID rsaEncryption;
            }
            namespace EncryptionAlgorithms {
                extern const OID pkcs5PBES2;
            }
            namespace KDFs {
                extern const OID pkcs5PBKDF2;
            }
            namespace HMACFunctions {
                extern const OID hmacWithSHA256;
            }
            namespace EncryptionSchemes {
                extern const OID aes128_CBC;
            }
        }
        namespace Enums {
            enum PrivateKeyAlgorithms : uint32_t {
                rsaEncryption = 0x0
            };
            enum EncryptionAlgorithms : uint32_t {
                pkcs5PBES2 = 0x1000
            };
            enum KDFs : uint32_t {
                pkcs5PBKDF2 = 0x2000
            };
            enum HMACFunctions : uint32_t {
                hmacWithSHA256 = 0x3000
            };
            enum EncryptionSchemes : uint32_t {
                aes128_CBC = 0x4000
            };
        }
        namespace Maps {
            extern const std::unordered_map<OID, Enums::PrivateKeyAlgorithms> privateKeyAlgorithmsMap;
            extern const std::unordered_map<OID, Enums::EncryptionAlgorithms> encryptionAlgorithmsMap;
            extern const std::unordered_map<OID, Enums::KDFs> kdfsMap;
            extern const std::unordered_map<OID, Enums::HMACFunctions> hmacFunctionsMap;
            extern const std::unordered_map<OID, Enums::EncryptionSchemes> encryptionSchemesMap;
        }
    }

    // Labels related to PKCS - headers/footers of PKCS-compatible files
    namespace Labels {
        extern const std::string privateKeyHeader;
        extern const std::string privateKeyFooter;
        extern const std::string encryptedPrivateKeyHeader;
        extern const std::string encryptedPrivateKeyFooter;
    }

    namespace PBES2 {

        struct AlgorithmIdentifier {
            uint32_t algorithm;
            std::shared_ptr<void> params;
        };

        struct PBKDF2Params {
            std::shared_ptr<std::vector<uint8_t>> salt;
            uint32_t iterationCount;
            struct AlgorithmIdentifier prf;
        };
    }

}