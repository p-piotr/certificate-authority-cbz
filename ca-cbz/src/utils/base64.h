#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include <span>

namespace CBZ::Base64 {

    // You guessed it - Base64 encoding/decoding
    // obvious functions
    std::string encode(std::span<const uint8_t> in);
    std::vector<uint8_t> decode(std::span<const char> in);
}