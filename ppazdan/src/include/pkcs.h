#pragma once

#include <string>
#include <cstdint>
#include "include/asn1.h"

// Namespace containing PKCS-related operations
namespace CBZ::PKCS {

    using namespace ASN1;

    // Common OIDs found inside PKCS objects; this is not a complete list
    namespace OID {
        extern std::string rsaEncryption;
        extern std::string pkcs5PBES2;
        extern std::string pkcs5PBKDF2;
        extern std::string hmacWithSHA256;
        extern std::string aes128_CBC;
    }

    // Labels related to PKCS - headers/footers of PKCS-compatible files
    namespace Labels {
        extern std::string privateKeyHeader;
        extern std::string privateKeyFooter;
        extern std::string encryptedPrivateKeyHeader;
        extern std::string encryptedPrivateKeyFooter;
    }

    // PKCS Types (tags)
    enum PKCSTag {
        Any,
        Version,
        PrivateKey,
        AlgorithmIdentifier,
    };

    // Converts a PKCS tag (enum) to string
    constexpr const char* tag_to_string(PKCSTag tag);

    namespace Structures {

        namespace PKCSVersion {
            constexpr uint32_t containerType = ASN1::ASN1Tag::INTEGER;
            constexpr uint32_t contents[] = {};
        }

        namespace PKCSAlgorithmIdentifier {
            constexpr uint32_t containerType = ASN1::ASN1Tag::SEQUENCE;
            constexpr uint32_t contents[] = { 
                ASN1::ASN1Tag::OBJECT_IDENTIFIER ,
                PKCS::PKCSTag::Any
            };
        }

    }

    namespace PKCSParser {

        bool is_object_valid_pkcs(
            std::shared_ptr<ASN1Object> object,
            PKCSTag pkcsObject
        );
    }
}