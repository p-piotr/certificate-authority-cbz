#pragma once

#include <array>
#include <concepts>
#include <cstddef>
#include <vector>
#include "include/sha.h"
#include "include/security.h"

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

        static _H::MD digest(uint8_t *message, size_t size, std::vector<uint8_t> const &key) {
            // small lambda function to perform XOR of every byte of arbitralily large array against a given value 'v'
            auto _xor_v = []<size_t _N>(std::array<uint8_t, _N> const &arr, uint8_t v) {
                auto arr_copy = arr;
                for (size_t i = 0; i < _N; i++)
                    arr_copy[i] ^= v;
                return arr_copy;
            };

            KEY derived_key = derive_blocksized_key(key);
            KEY derived_key_opad = _xor_v(derived_key, 0x5C), derived_key_ipad = _xor_v(derived_key, 0x36);
            std::vector<uint8_t> concat_message;
            // in concat_message we will store:
            // (K' ^ ipad) || m                           - sizeof(_H::BLOCK_SIZE) + size
            // (K' ^ opad) || H((K' ^ ipad) || m))        - sizeof(_H::BLOCK_SIZE) + sizeof(_H::MD)
            // so we can reserve the bigger size
            concat_message.reserve(
                size > sizeof(typename _H::MD) ? 
                sizeof(_H::BLOCK_SIZE) + size 
                : sizeof(_H::BLOCK_SIZE) + sizeof(typename _H::MD)
            );

            concat_message.insert(
                concat_message.cend(), 
                derived_key_ipad.begin(), 
                derived_key_ipad.end()
            );
            concat_message.insert(
                concat_message.cend(),
                message,
                message + size
            );
            typename _H::MD 
                inner_hash = _H::digest(concat_message.data(), concat_message.size());
            
            secure_zero_memory(derived_key.data(), derived_key.size());
            secure_zero_memory(derived_key_ipad.data(), derived_key_ipad.size());
            secure_zero_memory(concat_message.data(), concat_message.size());

            concat_message.resize(0);
            concat_message.insert(
                concat_message.cend(),
                derived_key_opad.begin(),
                derived_key_opad.end()
            );
            concat_message.insert(
                concat_message.cend(),
                inner_hash.begin(),
                inner_hash.end()
            );

            secure_zero_memory(derived_key_opad.data(), derived_key_opad.size());
            secure_zero_memory(inner_hash.data(), inner_hash.size());

            typename _H::MD result_hmac = _H::digest(concat_message.data(), concat_message.size());

            secure_zero_memory(concat_message.data(), concat_message.size());

            return result_hmac;
        }
    };
}