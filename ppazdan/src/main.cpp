#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include "base64.h"
#include "asn1.h"
#include "rsa.h"

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " [OBJECT IDENTIFIER]" << std::endl;
        return 1;
    }

    std::vector<uint8_t> obj_id = ASN1::ASN1ObjectIdentifier::encode(argv[1]);
    for (uint8_t ch : obj_id) {
        std::cout << std::setfill('0') << std::hex << static_cast<uint32_t>(ch) << ' ';
    }
    std::cout << std::endl;
    
    std::string obj_id_str = ASN1::ASN1ObjectIdentifier::decode(obj_id);
    std::cout << obj_id_str << std::endl;

    return 0;
}