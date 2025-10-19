#pragma once

#include <vector>
#include <cstdint>
#include <string>

class Base64 {
public:
    static std::string encode(char* buffer, size_t size);
    static std::vector<uint8_t> decode(std::string const& encoded_string);
    static inline bool is_base64(uint8_t c);
    static const std::string base64_chars;
};