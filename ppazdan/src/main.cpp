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

    RSA::RSAPrivateKey rsa_private_key;
    std::cout << "DECODING TEST" << std::endl << std::endl;

    try {
        std::string key_file_path = argv[1];
        rsa_private_key = RSA::RSAPrivateKey(key_file_path);
        rsa_private_key.print();

        std::vector<uint8_t> data = { 0x12, 0x34, 0x56 };
        ASN1::ASN1Object object(ASN1::ASN1Tag::INTEGER, std::move(data));
        object.print();
        std::cout << ASN1::ASN1Integer::decode(object.value()) << std::endl;
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    std::cout << std::endl << "----------------------------------------" << std::endl << std::endl;
    std::cout << "ENCODING TEST" << std::endl << std::endl;

    std::shared_ptr<ASN1::ASN1Object> pkey_version = std::make_shared<ASN1::ASN1Object>(ASN1::ASN1Tag::INTEGER, ASN1::ASN1Integer::encode(0));
    std::shared_ptr<ASN1::ASN1Object> n = std::make_shared<ASN1::ASN1Object>(ASN1::ASN1Tag::INTEGER, ASN1::ASN1Integer::encode(rsa_private_key.n()));
    std::shared_ptr<ASN1::ASN1Object> e = std::make_shared<ASN1::ASN1Object>(ASN1::ASN1Tag::INTEGER, ASN1::ASN1Integer::encode(rsa_private_key.e()));
    std::shared_ptr<ASN1::ASN1Object> d = std::make_shared<ASN1::ASN1Object>(ASN1::ASN1Tag::INTEGER, ASN1::ASN1Integer::encode(rsa_private_key.d()));
    std::shared_ptr<ASN1::ASN1Object> p = std::make_shared<ASN1::ASN1Object>(ASN1::ASN1Tag::INTEGER, ASN1::ASN1Integer::encode(rsa_private_key.p()));
    std::shared_ptr<ASN1::ASN1Object> q = std::make_shared<ASN1::ASN1Object>(ASN1::ASN1Tag::INTEGER, ASN1::ASN1Integer::encode(rsa_private_key.q()));
    std::shared_ptr<ASN1::ASN1Object> exponent1 = std::make_shared<ASN1::ASN1Object>(ASN1::ASN1Tag::INTEGER, ASN1::ASN1Integer::encode(rsa_private_key.exponent1()));
    std::shared_ptr<ASN1::ASN1Object> exponent2 = std::make_shared<ASN1::ASN1Object>(ASN1::ASN1Tag::INTEGER, ASN1::ASN1Integer::encode(rsa_private_key.exponent2()));
    std::shared_ptr<ASN1::ASN1Object> coefficient = std::make_shared<ASN1::ASN1Object>(ASN1::ASN1Tag::INTEGER, ASN1::ASN1Integer::encode(rsa_private_key.coefficient()));
    std::shared_ptr<ASN1::ASN1Object> pkey_sequence = std::make_shared<ASN1::ASN1Object>(ASN1::ASN1Tag::SEQUENCE, std::move(std::vector<std::shared_ptr<ASN1::ASN1Object>>({
        pkey_version,
        n,
        e,
        d,
        p,
        q,
        exponent1,
        exponent2,
        coefficient,

    })));
    std::shared_ptr<ASN1::ASN1Object> pkey_octet_string = std::make_shared<ASN1::ASN1Object>(ASN1::ASN1Tag::OCTET_STRING, std::move(std::vector<std::shared_ptr<ASN1::ASN1Object>>({ pkey_sequence })));
    std::shared_ptr<ASN1::ASN1Object> algorithm = std::make_shared<ASN1::ASN1Object>(ASN1::ASN1Tag::OBJECT_IDENTIFIER, ASN1::ASN1ObjectIdentifier::encode("1.2.840.113549.1.1.1"));
    std::shared_ptr<ASN1::ASN1Object> parameters = std::make_shared<ASN1::ASN1Object>(ASN1::ASN1Tag::NULL_TYPE);
    std::shared_ptr<ASN1::ASN1Object> private_key_algorithm = std::make_shared<ASN1::ASN1Object>(ASN1::ASN1Tag::SEQUENCE, std::move(std::vector<std::shared_ptr<ASN1::ASN1Object>>({ algorithm, parameters })));
    std::shared_ptr<ASN1::ASN1Object> version = std::make_shared<ASN1::ASN1Object>(ASN1::ASN1Tag::INTEGER, ASN1::ASN1Integer::encode(0));
    std::shared_ptr<ASN1::ASN1Object> private_key = std::make_shared<ASN1::ASN1Object>(ASN1::ASN1Tag::SEQUENCE, std::move(std::vector<std::shared_ptr<ASN1::ASN1Object>>({ version, private_key_algorithm, pkey_octet_string })));
    std::shared_ptr<std::vector<uint8_t>> encoded = ASN1::ASN1Parser::encode_all(private_key);
    std::cout << "Encoded ASN.1 SEQUENCE: ";
    for (uint8_t byte : *encoded) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << ' ';
    }
    std::cout << std::dec << std::endl;

    return 0;
}