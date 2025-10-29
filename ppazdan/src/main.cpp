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

    /*
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
        std::cout << ASN1::ASN1Integer::decode(object.value()) << std::endl;
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    */

    std::shared_ptr<ASN1::ASN1Object> val1 = std::make_shared<ASN1::ASN1Object>(ASN1::ASN1Tag::INTEGER, ASN1::ASN1Integer::encode(mpz_class("12345678901234567890")));
    std::shared_ptr<ASN1::ASN1Object> val2 = std::make_shared<ASN1::ASN1Object>(ASN1::ASN1Tag::INTEGER, ASN1::ASN1Integer::encode(mpz_class("98765432109876543210")));
    std::vector<std::shared_ptr<ASN1::ASN1Object>> children = { val1, val2 };
    std::shared_ptr<ASN1::ASN1Object> seq = std::make_shared<ASN1::ASN1Object>(ASN1::ASN1Tag::SEQUENCE, std::move(children));
    std::shared_ptr<std::vector<uint8_t>> encoded = ASN1::ASN1Parser::encode_all(seq);
    std::cout << "Encoded ASN.1 SEQUENCE: ";
    for (uint8_t byte : *encoded) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << ' ';
    }
    std::cout << std::dec << std::endl;

    return 0;
}