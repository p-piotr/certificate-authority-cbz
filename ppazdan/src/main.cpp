#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include "base64.h"
#include "asn1.h"
#include "rsa.h"
#include "security.h"

int main(int argc, char** argv) {
    mpz_initialize_secure();

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " [KEY FILE]" << std::endl;
        return 1;
    }

    try {
        std::string key_file_path = argv[1];
        RSA::RSAPrivateKey rsa_private_key = RSA::RSAPrivateKey(key_file_path);
        rsa_private_key.print();

        std::vector<uint8_t> data = { 0x12, 0x34, 0x56 };
        ASN1::ASN1Object object(ASN1::ASN1Tag::INTEGER, std::move(data));
        object.print();
        std::cout << ASN1::ASN1Integer::decode(object.object_data()) << std::endl;
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}