#pragma once

#include <array>
#include <concepts>
#include <cstddef>
#include <vector>
#include "include/sha.h"
#include "include/security.hpp"

namespace CBZ {

    template <typename _PRF>
    concept PseudoRandomFunction = requires(
        _PRF &prf,
        uint8_t const *m,
        size_t msize,
        uint8_t const *k,
        size_t ksize,
        uint8_t *od
    ) {
        { _PRF::KEY_SIZE } -> std::convertible_to<size_t>;
        { _PRF::DIGEST_SIZE } -> std::convertible_to<size_t>;

        { _PRF::digest(m, msize, k, ksize, od) } -> std::same_as<void>;
    };

    // Class describing a HMAC function template, based on given HashFunction object (interface implementation)
    template <HashFunction _H>
    class HMAC {
    public:
        static const constexpr size_t KEY_SIZE = _H::BLOCK_SIZE;
        static const constexpr size_t DIGEST_SIZE = _H::DIGEST_SIZE;

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
        static void derive_blocksized_key(
            uint8_t const *input_key,
            size_t input_key_size,
            uint8_t *derived_key
        ) {
            if (input_key_size == KEY_SIZE) {
                std::memcpy(
                    derived_key,
                    const_cast<uint8_t*>(input_key),
                    KEY_SIZE
                );
                return;
            }

            if (input_key_size < KEY_SIZE) {
                std::memcpy(
                    derived_key,
                    const_cast<uint8_t*>(input_key),
                    input_key_size
                );
                std::memset(
                    derived_key + input_key_size,
                    0,
                    KEY_SIZE - input_key_size
                );
                return;
            }

            _H::digest(input_key, input_key_size, derived_key);
            std::memset(
                const_cast<uint8_t*>(derived_key + DIGEST_SIZE),
                0,
                KEY_SIZE - DIGEST_SIZE
            );
        }

        // Calculates the HMAC
        //
        // Input:
        // @m - message
        // @msize - message size (in bytes)
        // @k - key
        // @ksize - key size (in bytes)
        // @od - out pointer to buffer storing the calculated HMAC
        //       this buffer MUST be of size at least DIGEST_SIZE
        static void digest(
            uint8_t const *m,
            size_t msize,
            uint8_t const *k,
            size_t ksize,
            uint8_t *od
        ) {
            // small lambda function to perform XOR of every byte of arbitralily large array against a given value 'v'
            auto _xor_v = [](uint8_t *ar, size_t ar_size, uint8_t v) {
                for (size_t i = 0; i < ar_size; i++)
                    ar[i] ^= v;
            };

            uint8_t 
                derived_key[KEY_SIZE],
                derived_key_opad[KEY_SIZE],
                derived_key_ipad[KEY_SIZE],
                inner_hash[DIGEST_SIZE];

            derive_blocksized_key(k, ksize, derived_key);
            std::memcpy(
                derived_key_opad,
                derived_key,
                KEY_SIZE
            );
            _xor_v(derived_key_opad, KEY_SIZE, 0x5C);
            std::memcpy(
                derived_key_ipad,
                derived_key,
                KEY_SIZE
            );
            _xor_v(derived_key_ipad, KEY_SIZE, 0x36);

            std::vector<uint8_t> concat_message;
            // in concat_message we will store:
            // (K' ^ ipad) || m                           - KEY_SIZE + msize
            // (K' ^ opad) || H((K' ^ ipad) || m))        - KEY_SIZE + DIGEST_SIZE
            // so we can reserve the bigger size
            concat_message.reserve(
                msize > DIGEST_SIZE ? 
                KEY_SIZE + msize 
                : KEY_SIZE + DIGEST_SIZE
            );

            concat_message.resize(KEY_SIZE + msize);
            std::memcpy(
                concat_message.data(),
                derived_key_ipad,
                KEY_SIZE
            );
            std::memcpy(
                concat_message.data() + KEY_SIZE,
                m,
                msize
            );
            _H::digest(concat_message.data(), concat_message.size(), inner_hash);
            
            secure_zero_memory(derived_key, KEY_SIZE);
            secure_zero_memory(derived_key_ipad, KEY_SIZE);

            concat_message.resize(KEY_SIZE + DIGEST_SIZE);
            std::memcpy(
                concat_message.data(),
                derived_key_opad,
                KEY_SIZE
            );
            std::memcpy(
                concat_message.data() + KEY_SIZE,
                inner_hash,
                DIGEST_SIZE
            );
            _H::digest(concat_message.data(), concat_message.size(), od);

            secure_zero_memory(derived_key_opad, KEY_SIZE);
            secure_zero_memory(inner_hash, DIGEST_SIZE);
            secure_zero_memory(concat_message.data(), concat_message.size());
        }
    };
}