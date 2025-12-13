#include <vector>
#include <cstdint>
#include <cstddef>
#include <span>
#include "base64.h"

namespace CBZ::Base64 {

    // Base64 allowed charset
    const std::string b = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    // Encodes a buffer into a Base64 string
    std::string encode(std::span<uint8_t> in) {
        std::string out;

        int val=0;
        int valb=-6;
        for (uint8_t c : in) {
            val = (val<<8) + c;
            valb += 8;
            while (valb>=0) {
                out.push_back(b[(val>>valb)&0x3F]);
                valb-=6;
            }
        }
        if (valb>-6) out.push_back(b[((val<<8)>>(valb+8))&0x3F]);
        while (out.size()%4) out.push_back('=');
        return out;
    }

    // Decodes a Base64 string into a buffer
    std::vector<uint8_t> decode(std::string const& in) {
        std::vector<uint8_t> out;

        std::vector<int> T(256,-1);
        for (int i=0; i<64; i++) T[b[i]] = i;

        int val=0;
        int valb=-8;
        for (uint8_t c : in) {
            if (T[c] == -1) break;
            val = (val<<6) + T[c];
            valb += 6;
            if (valb>=0) {
                out.push_back(char((val>>valb)&0xFF));
                valb-=8;
            }
        }
        return out;
    }
}