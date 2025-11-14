#include "include/pkcs.h"
#include "include/asn1.h"
#include <string>
#include <cstdint>

namespace CBZ::PKCS {

    namespace OID {
        std::string rsaEncryption = "1.2.840.113549.1.1.1";
        std::string pkcs5PBES2 = "1.2.840.113549.1.5.13";
        std::string pkcs5PBKDF2 = "1.2.840.113549.1.5.12";
        std::string hmacWithSHA256 = "1.2.840.113549.2.9";
        std::string aes128_CBC = "2.16.840.1.101.3.4.1.2";
    }

    namespace Labels {
        std::string privateKeyHeader = "-----BEGIN PRIVATE KEY-----";
        std::string privateKeyFooter = "-----END PRIVATE KEY-----";
        std::string encryptedPrivateKeyHeader = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
        std::string encryptedPrivateKeyFooter = "-----END ENCRYPTED PRIVATE KEY-----";
    }
}