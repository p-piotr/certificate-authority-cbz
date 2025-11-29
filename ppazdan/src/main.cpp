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
        std::cerr << "Usage: " << argv[0] << " KEY_FILE" << std::endl;
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

void AES_test() {
    std::array<uint8_t, 16> key = { 0x30, 0x30, 0x31, 0x31, 0x32, 0x32, 0x33, 0x33, 0x34, 0x34, 0x35, 0x35, 0x36, 0x36, 0x37, 0x37 };
    std::array<uint8_t, 16> iv = { 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30 };
    std::string message = "hello";
    std::vector<uint8_t> enc;
    AES::AES_128_CBC::encrypt(
        { reinterpret_cast<uint8_t*>(message.data()), message.size() },
        key.data(),
        iv.data(),
        enc
    );
    for (uint8_t b : enc)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    std::cout << std::endl;

    std::vector<uint8_t> dec;
    AES::AES_128_CBC::decrypt(
        std::span{enc},
        key.data(),
        iv.data(),
        dec
    );
    for (uint8_t b : dec)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);

    std::cout << std::endl;
}

void SHA_test(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " MESSAGE" << std::endl;
        return;
    }
    auto _dprint = [&](std::span<uint8_t const> s) {
        for (auto b : s)
            std::cerr << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b) << ' ';
        std::cerr << std::endl;
    };
    std::cout << "SHA1:" << std::endl;
    uint8_t digest1[SHA::SHA1::DIGEST_SIZE];
    SHA::SHA1::digest(std::span{reinterpret_cast<uint8_t*>(argv[1]), strlen(argv[1])}, digest1);
    _dprint(std::span{digest1});
    std::cout << "SHA256:" << std::endl;
    uint8_t digest256[SHA::SHA256::DIGEST_SIZE];
    SHA::SHA256::digest(std::span{reinterpret_cast<uint8_t*>(argv[1]), strlen(argv[1])}, digest256);
    _dprint(std::span{digest256});
}

void HMAC_test() {
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

void KDF_test() {
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
        rsa_private_key.print();
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return;
    }

    return;
}

void PBKDF2_SHA1_test1() {
    std::string p_str = "password";
    std::string s_str = "salt";
    uint32_t iterations = 1;
    uint32_t dkLen = 20;

    // Expected output from RFC 6070
    std::vector<uint8_t> expected = {
        0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9,
        0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6
    };

    std::vector<uint8_t> actual(dkLen);

    // Your call
    CBZ::KDF::PBKDF2<HMAC<SHA::SHA1>>::derive_key(
        std::span{reinterpret_cast<uint8_t const*>(p_str.data()), p_str.size()},
        std::span{reinterpret_cast<uint8_t const*>(s_str.data()), s_str.size()},
        iterations,
        dkLen,
        actual.data()
    );

    if (actual == expected) {
        std::cout << "✅ [PASS] RFC 6070 Test Vector #1" << std::endl;
    } else {
        std::cerr << "❌ [FAIL] RFC 6070 Test Vector #1" << std::endl;
    }
}

void PBKDF2_SHA1_test2() {
    std::string p_str = "password";
    std::string s_str = "salt";
    uint32_t iterations = 2;
    uint32_t dkLen = 20;

    // Expected output from RFC 6070
    std::vector<uint8_t> expected = {
        0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e,
        0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57
    };

    std::vector<uint8_t> actual(dkLen);

    CBZ::KDF::PBKDF2<HMAC<SHA::SHA1>>::derive_key(
        std::span{reinterpret_cast<uint8_t const*>(p_str.data()), p_str.size()},
        std::span{reinterpret_cast<uint8_t const*>(s_str.data()), s_str.size()},
        iterations,
        dkLen,
        actual.data()
    );

    if (actual == expected) {
        std::cout << "✅ [PASS] RFC 6070 Test Vector #2" << std::endl;
    } else {
        std::cerr << "❌ [FAIL] RFC 6070 Test Vector #2" << std::endl;
    }
}

void PBKDF2_SHA1_test3() {
    // Note: Use std::vector or explicit string construction to handle embedded nulls
    // "pass\0word" (9 bytes)
    std::vector<uint8_t> p = {'p', 'a', 's', 's', 0, 'w', 'o', 'r', 'd'};
    // "sa\0lt" (5 bytes)
    std::vector<uint8_t> s = {'s', 'a', 0, 'l', 't'};
    
    uint32_t iterations = 4096;
    uint32_t dkLen = 16;

    // Expected output from RFC 6070
    std::vector<uint8_t> expected = {
        0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x09, 0x9d,
        0xcc, 0x37, 0xd7, 0xf0, 0x34, 0x25, 0xe0, 0xc3
    };

    std::vector<uint8_t> actual(dkLen);

    CBZ::KDF::PBKDF2<HMAC<SHA::SHA1>>::derive_key(
        std::span{p},
        std::span{s},
        iterations,
        dkLen,
        actual.data()
    );

    if (actual == expected) {
        std::cout << "✅ [PASS] RFC 6070 Test Vector #3" << std::endl;
    } else {
        std::cerr << "❌ [FAIL] RFC 6070 Test Vector #3" << std::endl;
    }
}

void PBKDF2_SHA1_unittests() {
    PBKDF2_SHA1_test1();
    PBKDF2_SHA1_test2();
    PBKDF2_SHA1_test3();
}

void PBKDF2_SHA256_test1() {
    std::string p_str = "password";
    std::string s_str = "salt";
    uint32_t iterations = 1;
    uint32_t dkLen = 32;

    // Standard Vector for PBKDF2-HMAC-SHA256 (c=1, dkLen=32)
    std::vector<uint8_t> expected = {
        0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c,
        0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
        0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48,
        0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b
    };

    std::vector<uint8_t> actual(dkLen);

    // Note the change to SHA256 in the template argument
    CBZ::KDF::PBKDF2<HMAC<SHA::SHA256>>::derive_key(
        std::span{reinterpret_cast<uint8_t const*>(p_str.data()), p_str.size()},
        std::span{reinterpret_cast<uint8_t const*>(s_str.data()), s_str.size()},
        iterations,
        dkLen,
        actual.data()
    );

    if (actual == expected) {
        std::cout << "✅ [PASS] PBKDF2-HMAC-SHA256 Test Vector #1" << std::endl;
    } else {
        std::cerr << "❌ [FAIL] PBKDF2-HMAC-SHA256 Test Vector #1" << std::endl;
        std::cerr << "Expected: ";
        for(auto b : expected) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        std::cerr << "\nActual:   ";
        for(auto b : actual) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        std::cerr << std::dec << std::endl;
    }
}

void PBKDF2_SHA256_test2() {
    std::string p_str = "password";
    std::string s_str = "salt";
    uint32_t iterations = 2;
    uint32_t dkLen = 32;

    // Standard Vector for PBKDF2-HMAC-SHA256 (c=2, dkLen=32)
    std::vector<uint8_t> expected = {
        0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3,
        0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0,
        0x2a, 0x30, 0x3f, 0x8e, 0xf3, 0xc2, 0x51, 0xdf,
        0xd6, 0xe2, 0xd8, 0x5a, 0x95, 0x47, 0x4c, 0x43
    };

    std::vector<uint8_t> actual(dkLen);

    CBZ::KDF::PBKDF2<HMAC<SHA::SHA256>>::derive_key(
        std::span{reinterpret_cast<uint8_t const*>(p_str.data()), p_str.size()},
        std::span{reinterpret_cast<uint8_t const*>(s_str.data()), s_str.size()},
        iterations,
        dkLen,
        actual.data()
    );

    if (actual == expected) {
        std::cout << "✅ [PASS] PBKDF2-HMAC-SHA256 Test Vector #2" << std::endl;
    } else {
        std::cerr << "❌ [FAIL] PBKDF2-HMAC-SHA256 Test Vector #2" << std::endl;
    }
}

void PBKDF2_SHA256_test3() {
    std::string p_str = "password";
    std::string s_str = "salt";
    uint32_t iterations = 4096;
    uint32_t dkLen = 32;

    // Standard Vector for PBKDF2-HMAC-SHA256 (c=4096, dkLen=32)
    std::vector<uint8_t> expected = {
        0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41,
        0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d,
        0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11,
        0xa4, 0x96, 0x38, 0x73, 0xaa, 0x98, 0x13, 0x4a
    };

    std::vector<uint8_t> actual(dkLen);

    CBZ::KDF::PBKDF2<HMAC<SHA::SHA256>>::derive_key(
        std::span{reinterpret_cast<uint8_t const*>(p_str.data()), p_str.size()},
        std::span{reinterpret_cast<uint8_t const*>(s_str.data()), s_str.size()},
        iterations,
        dkLen,
        actual.data()
    );

    if (actual == expected) {
        std::cout << "✅ [PASS] PBKDF2-HMAC-SHA256 Test Vector #3" << std::endl;
    } else {
        std::cerr << "❌ [FAIL] PBKDF2-HMAC-SHA256 Test Vector #3" << std::endl;
    }
}

void PBKDF2_SHA256_unittests() {
    PBKDF2_SHA256_test1();
    PBKDF2_SHA256_test2();
    PBKDF2_SHA256_test3();
}

int main(int argc, char **argv) {
    mpz_initialize_secure();
    RSA_ASN1_test(argc, argv);
    //RSA_encrypted_test(argc, argv);
    return 0;
}