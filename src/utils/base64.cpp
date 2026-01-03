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
    std::string encode(std::span<const uint8_t> in) {
        std::string out;
        size_t real_outstring_size = 0;
        // helper lambda to push back a character along with newline every 64 characters (to the std::string out)
        auto _pushback_helper = [&](char c) {
            if (real_outstring_size % 64 == 0 && real_outstring_size > 0)
                out.push_back('\n');
            out.push_back(c);
            real_outstring_size++;
        };

        int val=0;
        int valb=-6;
        for (uint8_t c : in) {
            val = (val<<8) + c;
            valb += 8;
            while (valb>=0) {
                _pushback_helper(b[(val>>valb)&0x3F]);
                valb-=6;
            }
        }
        if (valb>-6) _pushback_helper(b[((val<<8)>>(valb+8))&0x3F]);
        while (real_outstring_size%4) _pushback_helper('=');
        return out;
    }

    // Decodes a Base64 string into a buffer
    // Also handles the string with '\n' characters
    // by simply ignoring them (helpful with .PEM files)
    std::vector<uint8_t> decode(std::span<const char> in) {
        std::vector<uint8_t> out;

        static const std::vector<int> T = []() {
            std::vector<int> table(256, -1);
            for (int i = 0; i < 64; i++) table[b[i]] = i;
            return table;
        }();

        int val=0;
        int valb=-8;
        for (char c : in) {
            unsigned char uc = static_cast<unsigned char>(c);
            if (uc == '\n') continue; // ignore newline characters
            if (T[uc] == -1) break;
            val = (val<<6) + T[uc];
            valb += 6;
            if (valb>=0) {
                out.push_back(static_cast<char>((val>>valb)&0xFF));
                valb-=8;
            }
        }
        return out;
    }
}