#include <array>
#include <cstddef>
#include <vector>
#include "include/hmac.h"
#include "include/sha.h"
#include "include/security.h"

namespace CBZ {
    
    template <HashFunction _H>
    HMAC<_H>::KEY HMAC<_H>::derive_blocksized_key(std::vector<uint8_t> const &key) {
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

    template <HashFunction _H>
    _H::MD HMAC<_H>::digest(uint8_t *message, size_t size, KEY const &key) {
        // TODO: implement xd
    }
}