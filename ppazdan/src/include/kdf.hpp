#pragma once

#include <array>
#include <cstdint>
#include "include/hmac.hpp"
#include "include/security.hpp"
#include "include/endianness.hpp"

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
        // @psize - password size (in bytes)
        // @s - salt to use
        // @ssize - salt size (in bytes)
        // @c - iteration count
        // @d_l - desired key length, in bytes
        // @out_key - out pointer to the buffer storing the derived key
        //            this buffer MUST be of size at least _dkLen bytes
        static void derive_key(
            uint8_t const *p,
            size_t psize,
            uint8_t const *s,
            size_t ssize,
            uint32_t c,
            uint32_t d_l,
            uint8_t *out_key
        ) {
            uint32_t num_blocks = static_cast<uint32_t>((d_l + hLen - 1) / hLen);
            uint8_t t[hLen];

            for (uint32_t i = 1; i < num_blocks; i++) {
                F(p, psize, s, ssize, c, i, t);
                std::memcpy(
                    out_key + ((i - 1) * hLen),
                    t,
                    hLen
                );
            }

            uint32_t bytes_left = d_l - ((num_blocks - 1) * hLen);
            F(p, psize, s, ssize, c, num_blocks, t);
            std::memcpy(
                out_key + ((num_blocks - 1) * hLen),
                t,
                bytes_left
            );
            secure_zero_memory(t, hLen);
        }

        // This function represents a single PBKDF2 iteration, according to the standard
        //
        // Input:
        // @p - password to derive key from
        // @psize - password size (in bytes)
        // @s - salt to use
        // @ssize - salt size (in bytes)
        // @c - total number of iterations
        // @i - current iteration number
        // @od - out pointer to the buffer holding the digest
        //       this buffer MUST be of size at least hLen (DIGEST_SIZE)
        static void F(
            uint8_t const *p,
            size_t psize,
            uint8_t const *s,
            size_t ssize,
            uint32_t c,
            uint32_t i,
            uint8_t *od
        ) {
            auto _xor_v = [](uint8_t *ar, uint8_t const *av, size_t s) {
                for (size_t i = 0; i < s; i++)
                    ar[i] ^= av[i];
            };

            //std::vector<uint8_t> first_data;
            std::vector<uint8_t> first_data;
            first_data.resize(ssize + 4);
            uint32_t i_be = to_bigendian(i);
            std::memcpy(
                first_data.data(),
                const_cast<uint8_t*>(s),
                ssize
            );
            std::memcpy(
                first_data.data() + ssize,
                &i_be,
                sizeof(i_be)
            );


            uint8_t u[hLen], u_i[hLen];
            _PRF::digest(first_data.data(), first_data.size(), p, psize, u);
            secure_zero_memory(first_data.data(), first_data.size());

            std::memcpy(
                od,
                u,
                hLen
            );
            for (uint32_t j = 2; j <= c; j++) {
                _PRF::digest(u, hLen, p, psize, u_i);
                //t_i ^= u_i;
                _xor_v(od, u_i, hLen);
                std::memcpy(
                    u,
                    u_i,
                    hLen
                );
            }
            secure_zero_memory(u, hLen);
            secure_zero_memory(u_i, hLen);
        }
    };
}