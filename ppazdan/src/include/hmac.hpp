#pragma once

#include <array>
#include <concepts>
#include <cstddef>
#include <vector>
#include <span>
#include "include/sha.h"
#include "include/security.hpp"

namespace CBZ {

    template <typename _PRF>
    concept PseudoRandomFunction = requires(
        std::span<uint8_t const> m,
        std::span<uint8_t const> k,
        uint8_t *od
    ) {
        { _PRF::KEY_SIZE } -> std::convertible_to<size_t>;
        { _PRF::DIGEST_SIZE } -> std::convertible_to<size_t>;

        { _PRF::digest(m, k, od) } -> std::same_as<void>;
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
        //     1) If key.size() == dk.size(), dk := key
        //     2) If key.size() < dk.size(), dk := key || 0_padding
        //     3) If key.size() > dk.size(), dk := H(key) || 0_padding (since DIGEST_SIZE < BLOCK_SIZE)
        //
        // Input:
        // @ik - key to derive from
        // @dk - pointer to the output derived key
        static void derive_blocksized_key(
            std::span<uint8_t const> ik,
            uint8_t *dk
        ) {
            if (ik.size() == KEY_SIZE) {
                std::memcpy(
                    dk,
                    ik.data(),
                    KEY_SIZE
                );
                return;
            }

            if (ik.size() < KEY_SIZE) {
                std::memcpy(
                    dk,
                    ik.data(),
                    ik.size()
                );
                std::memset(
                    dk + ik.size(),
                    0,
                    KEY_SIZE - ik.size()
                );
                return;
            }

            _H::digest(ik, dk);
            std::memset(
                dk + DIGEST_SIZE,
                0,
                KEY_SIZE - DIGEST_SIZE
            );
        }

        // Calculates the HMAC
        //
        // Input:
        // @m - message
        // @k - key
        // @od - out pointer to buffer storing the calculated HMAC
        //       this buffer MUST be of size at least DIGEST_SIZE
        static void digest(
            std::span<uint8_t const> m,
            std::span<uint8_t const> k,
            uint8_t *od
        ) {
            // small lambda function to perform XOR of every byte of arbitralily large array against a given value 'v'
            auto _xor_v = [](uint8_t *ar, size_t ar_size, uint8_t v) {
                for (size_t i = 0; i < ar_size; i++)
                    ar[i] ^= v;
            };

            uint8_t 
                dk[KEY_SIZE],
                dk_opad[KEY_SIZE],
                dk_ipad[KEY_SIZE],
                ihash[DIGEST_SIZE];

            derive_blocksized_key(k, dk);
            std::memcpy(
                dk_opad,
                dk,
                KEY_SIZE
            );
            _xor_v(dk_opad, KEY_SIZE, 0x5C);
            std::memcpy(
                dk_ipad,
                dk,
                KEY_SIZE
            );
            _xor_v(dk_ipad, KEY_SIZE, 0x36);

            std::vector<uint8_t> concat_message;
            // in concat_message we will store:
            // (K' ^ ipad) || m                           - KEY_SIZE + msize
            // (K' ^ opad) || H((K' ^ ipad) || m))        - KEY_SIZE + DIGEST_SIZE
            // so we can reserve the bigger size
            concat_message.reserve(
                m.size() > DIGEST_SIZE ?
                KEY_SIZE + m.size()
                : KEY_SIZE + DIGEST_SIZE
            );

            concat_message.resize(KEY_SIZE + m.size());
            std::memcpy(
                concat_message.data(),
                dk_ipad,
                KEY_SIZE
            );
            std::memcpy(
                concat_message.data() + KEY_SIZE,
                m.data(),
                m.size()
            );
            _H::digest(concat_message, ihash);
            
            secure_zero_memory(dk, KEY_SIZE);
            secure_zero_memory(dk_ipad, KEY_SIZE);

            concat_message.resize(KEY_SIZE + DIGEST_SIZE);
            std::memcpy(
                concat_message.data(),
                dk_opad,
                KEY_SIZE
            );
            std::memcpy(
                concat_message.data() + KEY_SIZE,
                ihash,
                DIGEST_SIZE
            );
            _H::digest(std::span{concat_message}, od);

            secure_zero_memory(dk_opad, KEY_SIZE);
            secure_zero_memory(ihash, DIGEST_SIZE);
            secure_zero_memory(concat_message.data(), concat_message.size());
        }
    };
}