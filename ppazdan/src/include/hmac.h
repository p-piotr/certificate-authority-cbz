#pragma once

#include <array>
#include <concepts>
#include <cstddef>
#include <vector>
#include "include/sha.h"

namespace CBZ {

    // Class describing a HMAC function template, based on given HashFunction object (interface implementation)
    template <HashFunction _H>
    class HMAC {
    public:
        typedef std::array<uint8_t, _H::BLOCK_SIZE> KEY; // Derived key used with the HMAC is always of internal block size
        // This class is not intended to be instantianized
        HMAC() = delete;
        ~HMAC() = delete;

        // Derive key to use with the HMAC, based on provided key
        // Essentially this comes down to 3 cases:
        //     1) If key.size() == derived_key.size(), derived_key := key
        //     2) If key.size() < derived_key.size(), derived_key := key || 0_padding
        //     3) If key.size() > derived_key.size(), derived_key := H(key) || 0_padding (since DIGEST_SIZE < BLOCK_SIZE)
        //
        // Input:
        // @key: Key to derive from, as a byte vector
        static KEY derive_blocksized_key(std::vector<uint8_t> const &key);

        static _H::MD digest(uint8_t *message, size_t size, KEY const &key);
    };

    // Explicit instantiations for the HMAC template specializations that are
    // used by other translation units (so the linker has concrete symbols).
    // If you add more HMAC usages with other hash types, add them here.
    template class HMAC<SHA::SHA224>;
    template class HMAC<SHA::SHA256>;
}