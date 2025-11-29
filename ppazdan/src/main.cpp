#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <span>
#include "include/base64.h"
#include "include/asn1.h"
#include "include/private_key.h"
#include "include/security.hpp"
#include "include/sha.h"
#include "include/aes.h"
#include "include/hmac.hpp"
#include "include/kdf.hpp"

using namespace CBZ;

void RSA_ASN1_test(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " KEY_FILE [KEY_FILE2]" << std::endl;
        return;
    }

    CBZ::RSA::RSAPrivateKey rsa_private_key;
    std::cout << "DECODING TEST" << std::endl << std::endl;

    try {
        std::string key_file_path = argv[1];
        rsa_private_key = CBZ::RSA::RSAPrivateKey(key_file_path);
        rsa_private_key.print();

        std::vector<uint8_t> data = { 0x12, 0x34, 0x56 };
        ASN1::ASN1Object object(ASN1::ASN1Tag::INTEGER, std::move(data));
        object.print();
        std::cout << ASN1::ASN1Integer::decode(object.value()) << std::endl;
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return;
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
}

void AES_test(int argc, char **argv) {
    std::array<uint8_t, 16> key = { 0x30, 0x30, 0x31, 0x31, 0x32, 0x32, 0x33, 0x33, 0x34, 0x34, 0x35, 0x35, 0x36, 0x36, 0x37, 0x37 };
    std::array<uint8_t, 16> iv = { 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30 };
    std::string message = "hello";
    std::vector<uint8_t> enc = AES::AES_128_CBC::encrypt({ reinterpret_cast<uint8_t*>(message.data()), message.size() }, key.data(), iv.data());
    for (uint8_t b : enc)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);

    std::cout << std::endl;
}

void SHA_test(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " MESSAGE" << std::endl;
        return;
    }
    typedef CBZ::SHA::SHA1 HF;
    uint8_t digest[HF::DIGEST_SIZE];
    HF::digest(std::span{reinterpret_cast<uint8_t*>(argv[1]), strlen(argv[1])}, digest);
    for (uint8_t b : digest)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    std::cout << std::endl;
}

void HMAC_test(int argc, char **argv) {
    auto print_vector = [&](std::vector<uint8_t> const &v) {
        for (uint8_t b : v)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b) << ' ';
        std::cout << std::dec << "    (size=" << v.size() << ')' << std::endl;
    };
    auto print_array = [&]<size_t _N>(const uint8_t (&v)[_N]) {
        for (uint8_t b : v)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b) << ' ';
        std::cout << std::dec << "    (size=" << _N << ')' << std::endl;
    };
    auto test = [&](std::vector<uint8_t> const &key) {
        uint8_t derived_key[HMAC<SHA::SHA256>::KEY_SIZE];
        HMAC<SHA::SHA256>::derive_blocksized_key(std::span{key}, derived_key);
        print_array(derived_key);
    };

    std::vector<uint8_t> key1 = { 0x55 };
    std::vector<uint8_t> key2(63, 0x55);
    std::vector<uint8_t> key3(64, 0x55);
    std::vector<uint8_t> key4(65, 0x55);
    test(key1);
    test(key2);
    test(key3);
    test(key4);

    std::string message = "hello";
    uint8_t hmac[HMAC<SHA::SHA256>::DIGEST_SIZE]; 
    HMAC<SHA::SHA256>::digest(
        std::span{reinterpret_cast<uint8_t*>(message.data()), message.size()},
        std::span{key1},
        hmac
    );   
    print_array(hmac);
}

void KDF_test(int argc, char **argv) {
    const size_t KEY_SIZE = 256;
    std::string password = "password1234";
    std::string salt = "mysuperduperhipersalt88274648";
    uint8_t derived_key[KEY_SIZE];
    CBZ::KDF::PBKDF2<CBZ::HMAC<CBZ::SHA::SHA256>>::derive_key(
        { reinterpret_cast<uint8_t*>(password.data()), password.size() },
        { reinterpret_cast<uint8_t*>(salt.data()), salt.size() },
        1024,
        KEY_SIZE,
        derived_key
    );
    for (auto b : derived_key)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b) << ' ';

    std::cout << std::endl;
}

void RSA_encrypted_test(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " ENCRYPTED_KEY_FILE" << std::endl;
        return;
    }
    try {
        std::string encrypted_key_filepath = argv[1];
        CBZ::RSA::RSAPrivateKey rsa_private_key(encrypted_key_filepath);
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return;
    }

    return;
}

int main(int argc, char **argv) {
    mpz_initialize_secure();
    RSA_encrypted_test(argc, argv);
    return 0;
}