#include <iostream>
#include <vector>
#include "asn1/asn1.h"
#include "pkcs/public_key.h"

namespace CBZ::PKCS {

    // Example: RSAPublicKey: = {n: 1234123412341234123412341234123413241234134, e: 12384123841239412342314823041234218}
    std::ostream& operator<<(std::ostream& os, const RSAPublicKey& pk){
        os << "RSAPublicKey: = {n: " << pk.n() << ", e: " << pk.e() << "}";
        return os;
    }

    ASN1Object RSAPublicKey::to_asn1() const {
        return ASN1BitString(
            ASN1Sequence({
                ASN1Integer(n()),
                ASN1Integer(e())
            }).encode()
        );
    }

    std::vector<uint8_t> RSAPublicKey::encode() const {
        return to_asn1().encode();
    }

    void RSAPublicKey::print() const {
        std::cout << "Modulus (n): " << n() << std::endl;
        std::cout << "Public Exponent (e): " << e() << std::endl;
    }
}