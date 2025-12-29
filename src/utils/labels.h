#pragma once

#include <string>

// This file simply contains string literals that can be found at the top of PEM file

namespace CBZ::PKCS::Labels {
inline const std::string privateKeyHeader =
    "-----BEGIN PRIVATE KEY-----";
inline const std::string privateKeyFooter =
    "-----END PRIVATE KEY-----";
inline const std::string encryptedPrivateKeyHeader =
    "-----BEGIN ENCRYPTED PRIVATE KEY-----";
inline const std::string encryptedPrivateKeyFooter =
    "-----END ENCRYPTED PRIVATE KEY-----";
inline const std::string certificateRequestHeader =     
    "-----BEGIN CERTIFICATE REQUEST-----";
inline const std::string certificateRequestFooter =    
    "-----END CERTIFICATE REQUEST-----";
}
