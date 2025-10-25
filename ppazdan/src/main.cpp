#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include "base64.h"
#include "asn1.h"
#include "rsa.h"

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " [KEY FILE]" << std::endl;
        return 1;
    }

    std::ifstream key_file(argv[1]);
    std::string key_asn1_b64 = "";
    std::string line;

    while (std::getline(key_file, line)) {
        if (line == RSA::private_key_header || line == RSA::private_key_footer) {
            continue;
        }
        key_asn1_b64 += line;
    }

    std::vector<uint8_t> key_asn1 = Base64::decode(key_asn1_b64);
    auto root_object = ASN1::ASN1Parser::decode_all(key_asn1, 0);
    if (!RSA::_RSAPrivateKey_format_check(root_object)) {
        std::cerr << "Invalid RSA private key format" << std::endl;
        return 2;
    }
    else {
        std::cout << "RSA private key format looks good!" << std::endl;
    }

    return 0;
}