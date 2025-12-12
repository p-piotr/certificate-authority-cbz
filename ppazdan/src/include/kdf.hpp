#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <iostream>
#include <iomanip>
#include "include/hmac.hpp"
#include "include/security.hpp"
#include "include/endianness.hpp"
#include "include/debug.h"

namespace CBZ::KDF {

    template<PseudoRandomFunction _PRF>
    class PBKDF2 {
    public:
        static const constexpr uint32_t hLen = static_cast<uint32_t>(_PRF::DIGEST_SIZE);

        PBKDF2() = delete;
        ~PBKDF2() = delete;

        // Derives the key according to PBKDF2 specification
        //
        // Input:
        // @p - password to derive key from
        // @s - salt to use
        // @c - iteration count
        // @dl - desired key length, in bytes
        // @ok - out pointer to the buffer storing the derived key
        //            this buffer MUST be of size at least _dkLen bytes
        static void derive_key(
            std::span<uint8_t const> p,
            std::span<uint8_t const> s,
            uint32_t c,
            uint32_t dl,
            uint8_t *ok
        ) {
            #ifdef KDF_DEBUG
            auto _dprint = [&](std::span<uint8_t const> s) {
                for (auto b : s)
                    std::cerr << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b) << ' ';
                std::cerr << std::endl;
            };
            std::cerr << std::endl << "[CBZ::KDF::derive_key]" << std::endl << "password: ";
            _dprint(p);
            std::cerr << "salt: ";
            _dprint(s);
            std::cerr << std::dec << std::endl;
            #endif // KDF_DEBUG

            uint32_t num_blocks = static_cast<uint32_t>((dl + hLen - 1) / hLen);
            uint8_t t[hLen];

            for (uint32_t i = 1; i < num_blocks; i++) {
                F(p, s, c, i, t);
                std::memcpy(
                    ok + ((i - 1) * hLen),
                    t,
                    hLen
                );
            }

            uint32_t bytes_left = dl - ((num_blocks - 1) * hLen);
            F(p, s, c, num_blocks, t);
            std::memcpy(
                ok + ((num_blocks - 1) * hLen),
                t,
                bytes_left
            );
            secure_zero_memory(t, hLen);
        }

        // This function represents a single PBKDF2 iteration, according to the standard
        //
        // Input:
        // @p - password to derive key from
        // @s - salt to use
        // @c - total number of iterations
        // @i - current iteration number
        // @od - out pointer to the buffer holding the digest
        //       this buffer MUST be of size at least hLen (DIGEST_SIZE)
        static void F(
            std::span<uint8_t const> p,
            std::span<uint8_t const> s,
            uint32_t c,
            uint32_t i,
            uint8_t *od
        ) {
            auto _xor_v = [](uint8_t *ar, uint8_t const *av, size_t s) {
                for (size_t i = 0; i < s; i++)
                    ar[i] ^= av[i];
            };

            std::vector<uint8_t> first_data;
            first_data.resize(s.size() + 4);
            uint32_t i_be = to_bigendian(i);
            std::memcpy(
                first_data.data(),
                s.data(),
                s.size()
            );
            std::memcpy(
                first_data.data() + s.size(),
                &i_be,
                sizeof(i_be)
            );


            uint8_t u[hLen], u_i[hLen];
            _PRF::digest(std::span{first_data}, p, u);
            secure_zero_memory(std::span{first_data});

            std::memcpy(
                od,
                u,
                hLen
            );
            for (uint32_t j = 2; j <= c; j++) {
                _PRF::digest(std::span{u}, p, u_i);
                //t_i ^= u_i;
                _xor_v(od, u_i, hLen);
                std::memcpy(
                    u,
                    u_i,
                    hLen
                );
            }
            secure_zero_memory(std::span{u});
            secure_zero_memory(std::span{u_i});
        }
    };
}