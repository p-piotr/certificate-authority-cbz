#pragma once

#include <string>

// Labels related to PKCS - headers/footers of PKCS-compatible files
namespace CBZ::PKCS::Labels {
    inline const std::string private_key_header = "-----BEGIN PRIVATE KEY-----\n";
    inline const std::string private_key_footer = "-----END PRIVATE KEY-----\n";
    inline const std::string encrypted_private_key_header = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n";
    inline const std::string encrypted_private_key_footer = "-----END ENCRYPTED PRIVATE KEY-----\n";
    inline const std::string csr_header = "-----BEGIN CERTIFICATE REQUEST-----\n";
    inline const std::string csr_footer = "-----END CERTIFICATE REQUEST-----\n";
    inline const std::string certificate_header = "-----BEGIN CERTIFICATE-----\n";
    inline const std::string certificate_footer = "-----END CERTIFICATE-----\n";
}
