#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include <span>

namespace CBZ {

    // You guessed it - Base64 encoding/decoding
    class Base64 {
    public:
        // obvious functions
        static std::string encode(std::span<char> buffer);
        static std::vector<uint8_t> decode(std::string const& encoded_string);

        // helper to check if a character is valid in base64 encoding
        static inline bool is_base64(uint8_t c);

        // base64 character set
        static const std::string base64_chars;
    };
}