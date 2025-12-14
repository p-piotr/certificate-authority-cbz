#include <array>
#include <stdexcept>
#include <sstream>
#include <span>
#include <openssl/evp.h>
#include <vector>
#include <cstring>
#include <cstdint>
#include "hash/sha.h"

namespace CBZ::SHA {

    // This is a generic SHA digest template function capable 
    // of digesting messages for multiple digest sizes,
    // outputting the digest itself as some MD - see above
    //
    // Input:
    // @md - EVP_MD* message digest object used internally by OpenSSL
    // @class_name - name of the class implementing this template - used
    //               only to print clear error debug logs
    // @m - message to digest
    // @od - pointer to the buffer storing digest; it MUST
    //               be able to contain at least DIGEST_SIZE bytes
    void _SHA_digest_generic(
        EVP_MD* md,
        char const* class_name,
        std::span<uint8_t const> m,
        uint8_t* od
    ) {
        EVP_MD_CTX* ctx = nullptr;
        int ret = 1;

        ctx = EVP_MD_CTX_new();
        if (ctx == nullptr)
            goto err;

        if (md == nullptr)
            goto err;

        if (!EVP_DigestInit_ex(ctx, md, nullptr))
            goto err;

        if (!EVP_DigestUpdate(ctx, m.data(), m.size()))
            goto err;

        if (!EVP_DigestFinal_ex(ctx, od, nullptr))
            goto err;

        ret = 0;

        err:
        EVP_MD_CTX_free(ctx);
        if (ret != 0) {
            std::stringstream err_msg;
            err_msg << "[" << class_name << "::digest] Error while digesting";
            throw std::runtime_error(err_msg.str());
        }
    }

    // See "sha.h" for further documentation, if needed

    void SHA1::digest(std::span<uint8_t const> m, uint8_t* od) {
        static _EVP_MD_wrapper sha1(nullptr, "SHA1", nullptr);
        _SHA_digest_generic(sha1.md(), "SHA1", m, od);
    }

    void SHA224::digest(std::span<uint8_t const> m, uint8_t* od) {
        static _EVP_MD_wrapper sha224(nullptr, "SHA224", nullptr);
        _SHA_digest_generic(sha224.md(), "SHA224", m, od);
    }

    void SHA256::digest(std::span<uint8_t const> m, uint8_t* od) {
        static _EVP_MD_wrapper sha256(nullptr, "SHA256", nullptr);
        _SHA_digest_generic(sha256.md(), "SHA256", m, od);
    }

    namespace Archive {

        // Copied from wikipedia
        // Look here for more information
        // https://en.wikipedia.org/wiki/SHA-2#Pseudocode

        const static std::array<uint32_t,64> k{
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };


        // rotate right
        // https://en.wikipedia.org/wiki/Bitwise_operation#Rotate
        static inline uint32_t rotr(uint32_t x, size_t n){
            return (x >> n) | (x << (32 - n));
        }


        // simply checks if value is stored as big endian or little endian
        // https://stackoverflow.com/questions/1001307/detecting-endianness-programmatically-in-a-c-program
        static inline bool is_big_endian(){
            union {
                uint32_t i;
                char c[4];
            } bint = {0x01020304};

            return bint.c[0] == 1;
        }


        // technically there should be check if the message isn't too long but that's pretty much not possible so IDGAF
        std::vector<uint8_t> sha256_digest(const std::vector<uint8_t>& input){
            std::array<uint32_t, 8> H = {
                0x6a09e667,
                0xbb67ae85,
                0x3c6ef372,
                0xa54ff53a,
                0x510e527f,
                0x9b05688c,
                0x1f83d9ab,
                0x5be0cd19
            };

            // calculate padding length

            // how many bytes we needed to get 64
            size_t mod_len = input.size() % 64;

            // 2 cases
            //
            // if mod_len is than 56  message_length will fit in this block hence 56 - mod_len
            // we always have to add pad the 0x80 byte hence strict inequality
            //
            // if greater on equal we have to pad to the next block hence the 120 - mod_len
            size_t pad_len = (mod_len < 56) ? (56 - mod_len) : (120 - mod_len); 

            // add padding
            std::vector<uint8_t> padded(input.begin(), input.end());
            padded.resize(padded.size() + pad_len + 8);

            // add 0x80 byte
            padded[input.size()] = 0x80;
            // add 0x00 bytes
            std::fill(padded.begin() + input.size() + 1, padded.end() - 8, 0x00);

            // add message length
            uint64_t message_length = static_cast<uint64_t>(input.size() * 8);

            // We need to check if uint64 message_length is stored in big endian
            if(!is_big_endian()){
                // https://stackoverflow.com/questions/105252/how-do-i-convert-between-big-endian-and-little-endian-values-in-c
                message_length = __builtin_bswap64(message_length);
            }
            // append message_length 
            std::memcpy(
                &padded[padded.size() - 8],
                &message_length,
                sizeof(message_length)
            );

            std::array<uint8_t, 32> digest;
            std::array<uint32_t,64> w;
            for(size_t chunk = 0; chunk < padded.size(); chunk += 64){

                // adding padded chunk into first 16 entries of w;
                for(size_t w_index = 0; w_index < 16; w_index++){
                    w[w_index] = (padded[chunk + 4*w_index + 0] << 24)
                        | (padded[chunk + 4*w_index + 1] << 16)
                        | (padded[chunk + 4*w_index + 2] << 8)
                        | (padded[chunk + 4*w_index + 3]);
                }

                // calculate the rest of w using hashing operations
                for(size_t i = 16; i < 64; i++){
                    uint32_t s0 = (rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3));
                    uint32_t s1 = (rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10));
                    w[i] = w[i-16] + s0 + w[i-7] + s1;
                }

                // store state (value h0-h7) into working variables
                uint32_t a = H[0];
                uint32_t b = H[1];
                uint32_t c = H[2];
                uint32_t d = H[3];
                uint32_t e = H[4];
                uint32_t f = H[5];
                uint32_t g = H[6];
                uint32_t h = H[7];

                // more hashing operations
                for(int i = 0; i < 64; i++){
                    uint32_t s1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25));
                    uint32_t ch = (e & f) ^ ((~e) & g);
                    uint32_t temp1 = (h + s1 + ch + k[i] + w[i]);
                    uint32_t s0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22));
                    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                    uint32_t temp2 = s0 + maj;
                    h = g;
                    g = f;
                    f = e;
                    e = d + temp1;
                    d = c;
                    c = b;
                    b = a;
                    a = temp1 + temp2;
                }

                // update state
                H[0] = H[0] + a;
                H[1] = H[1] + b;
                H[2] = H[2] + c;
                H[3] = H[3] + d;
                H[4] = H[4] + e;
                H[5] = H[5] + f;
                H[6] = H[6] + g;
                H[7] = H[7] + h;
            }

            // convert bytes to big-endian bytes
            for (size_t i = 0; i < 8; ++i) {
                digest[i * 4 + 0] = static_cast<uint8_t>((H[i] >> 24)  & 0xFF);
                digest[i * 4 + 1] = static_cast<uint8_t>((H[i] >> 16)  & 0xFF);
                digest[i * 4 + 2] = static_cast<uint8_t>((H[i] >> 8)   & 0xFF);
                digest[i * 4 + 3] = static_cast<uint8_t>((H[i] >> 0)   & 0xFF);
            }

            // return digest as vector (that's what is needed)
            return std::vector<uint8_t>(digest.begin(), digest.end());
        }
    }
}