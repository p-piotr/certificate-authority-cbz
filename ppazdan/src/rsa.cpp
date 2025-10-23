#include <iostream>
#include <cstdint>
#include <vector>
#include <fstream>
#include <gmpxx.h>
#include "rsa.h"
#include "base64.h"

// Contains all functionality related to RSA
namespace RSA {

    // Header and footer of a valid PKCS#8 private key
    std::string private_key_header = "-----BEGIN PRIVATE KEY-----";
    std::string private_key_footer = "-----END PRIVATE KEY-----";

    // Loads an RSA private key from file
    // TODO: finish
    RSAPrivateKey RSAPrivateKey::from_file(std::string const &filepath) {
        std::ifstream keyfile(filepath);
        std::string line1, line2, key_asn1_b64 = "";

        std::getline(keyfile, line1);
        if (line1 != RSA::private_key_header) {
            throw std::runtime_error("RSA private key header doesn't match the standard");
        }

        std::getline(keyfile, line1);
        while (std::getline(keyfile, line2)) {
            key_asn1_b64 += line1;
            line1 = line2;
        }

        std::vector<uint8_t> key_asn1 = Base64::decode(key_asn1_b64);

    }

}