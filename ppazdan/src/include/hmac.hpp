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
        static KEY derive_blocksized_key(std::vector<uint8_t> const &key) {
            constexpr size_t derived_key_size = _H::BLOCK_SIZE;
            std::array<uint8_t, derived_key_size> derived_key; // decltype(std::array<uint8_t, derived_key_size>) = decltype(_H::MD)

            if (key.size() == derived_key_size) {
                std::copy_n(key.begin(), derived_key_size, derived_key.begin());
                return derived_key;
            }

            if (key.size() < derived_key_size) {
                std::copy_n(key.begin(), key.size(), derived_key.begin());
                std::fill_n(
                    derived_key.begin() + key.size(),
                    derived_key_size - key.size(),
                    0
                );
                return derived_key;
            }

            constexpr const size_t digest_size = _H::DIGEST_SIZE;
            typename _H::MD hashed_key = _H::digest(key.data(), key.size());
            std::copy_n(hashed_key.begin(), digest_size, derived_key.begin());
            std::fill_n(
                derived_key.begin() + digest_size,
                derived_key_size - digest_size,
                0
            );
            secure_zero_memory(hashed_key.data(), _H::DIGEST_SIZE);
            return derived_key;
        }

        static _H::MD digest(uint8_t *message, size_t size, KEY const &key);
    };
}