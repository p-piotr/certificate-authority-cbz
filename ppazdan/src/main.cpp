#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include "base64.h"
#include "asn1.h"
#include "rsa.h"

void mpz_initialize_secure() {
    // Set custom memory deallocation function for GMP to ensure sensitive data is cleared from memory
    mp_set_memory_functions(nullptr, nullptr, RSA::secure_free);
}

int main(int argc, char** argv) {
    mpz_initialize_secure();

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " [KEY FILE]" << std::endl;
        return 1;
    }

    try {
        RSA::RSAPrivateKey private_key = RSA::RSAPrivateKey(argv[1]);
        std::cout << "RSA Private Key loaded successfully." << std::endl;
        private_key.print();
    } catch (const std::exception &e) {
        std::cerr << "Error loading RSA Private Key: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}