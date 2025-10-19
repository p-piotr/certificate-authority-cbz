#include <iostream>
#include "base64.h"
#include "asn1.h"

int main() {
    std::vector<uint8_t> asn1_data = { 0x30, 0x09, 0x02, 0x01, 0x07, 0x02, 0x01, 0x08, 0x02, 0x01, 0x09 };
    std::shared_ptr<ASN1Object> root = ASN1Parser::parseAll(asn1_data);
    return 0;
}