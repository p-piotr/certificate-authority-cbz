#pragma once

#include <string>

// Labels related to PKCS - headers/footers of PKCS-compatible files
namespace CBZ::PKCS::Labels {
    inline const std::string privateKeyHeader = "-----BEGIN PRIVATE KEY-----\n";
    inline const std::string privateKeyFooter = "-----END PRIVATE KEY-----\n";
    inline const std::string encryptedPrivateKeyHeader = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n";
    inline const std::string encryptedPrivateKeyFooter = "-----END ENCRYPTED PRIVATE KEY-----\n";
}
