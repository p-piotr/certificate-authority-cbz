#include <vector>
#include <gmpxx.h>
#include <stdexcept>
#include "sign.h"
#include "utils/security.hpp"
#include "pkcs/public_key.h"
#include "pkcs/private_key.h"
#include "pkcs/pkcs.h"
#include "hash/sha.h"


namespace CBZ::PKCS::Signature {

    // https://datatracker.ietf.org/doc/html/rfc8017#section-4.2
    // converts an octet/byte string to a nonnegative integer.
    // @in - vector of bytes to convert from
    // return value: converted integer
    static mpz_class OS2IP(const std::vector<uint8_t>& in){
        // as with decode_der_integer
        // I previously was doing this manually
        mpz_class out;
        mpz_import(
            out.get_mpz_t(),    // mpz_class into which data will be imported
            in.size(),          // number of words to import
            1,                  // 1=MSB first, -1=LSB first
            sizeof(uint8_t),    // size of each word in bytes
            1,                  // endianness within each word, 1 = big
            0,                  // how many MSB bits of each word should be set zero
            in.data()           // pointer to array read words from
        );

        return out;
    }

    // https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
    // converts an octet/byte string to a nonnegative integer.
    // @in - integer to convert
    // @xLen - intended length of output
    static std::vector<uint8_t> I2OSP(const mpz_class& in, size_t xLen){
        // can't be used to convert negative integers
        if (in < 0) {
            throw std::runtime_error("[I2OSP] Integer must be nonnegative");
        }

        // check if integer will fit in requested xLen
        size_t bytes_count = (mpz_sizeinbase(in.get_mpz_t(), 2) + 7)/8;
        if (bytes_count > xLen) {
            throw std::runtime_error("[I2OSP] Integer too large");
        }


        // as with encode_der_integer
        // I previously was doing this manually
        
        std::vector<uint8_t> out(xLen, 0);
        size_t written;

        mpz_export(
            out.data()  +               // pointer to array into which we will export
            (xLen - bytes_count),       // right allign data if xLen is greater than byte count of integer
        & written,                   // will hold number of words exported by the function
            1,                          // 1=MSB first, -1=LSB first
            sizeof(uint8_t),            // size of each word in bytes
            1,                          // endianness within each word, 1 = big
            0,                          // how many MSB bits of each word should be set zero; not needed here
            in.get_mpz_t()              // mpz_t to copy words from
        );

        // if less bytes were written something must have wrong
        if(written != bytes_count)
            throw std::runtime_error("[I2OSP] Wrong number of bytes written");

        return out;
    }

    // https://datatracker.ietf.org/doc/html/rfc8017#section-5.2.1
    // This function produces signature representative from message representative
    // Note that representative means an integer that corresponds to a given octet string
    // this function is RSA decryption operation however it doesn't use the "standard" s = m^d mod n
    // but the "optimized" version based on Chinese Reminder Theorem (look step 2b in RFC)
    // also note that value r_i, d_i and t_i are not present (they are used for multi-prime RSA)
    // @K - private key object that holds all values such as n, p, q, e etc.
    // @m - message representative
    // return value: integer representative of the signature
    static mpz_class RSAPS1(const RSAPrivateKey& K, const mpz_class& m){
        // get all the needed values
        const mpz_class& n = K.n();
        const mpz_class& p = K.p();
        const mpz_class& q = K.q();
        const mpz_class& qInv = K.coefficient();
        const mpz_class& dP = K.exponent1();
        const mpz_class& dQ = K.exponent2();

        // message representative cannot be 0 nor can it be greater than n (RSA wouldn't work)
        if (m < 0 || m >= n) {
            throw std::runtime_error("[RSAPS1] Message representative isn't in correct range");
        }

        // Sanity checks:
        // they can be removed if not needed
        // or more can be added
        {
            // Check if q * qInv = 1 mod p
            {
                mpz_class chk;
                mpz_mul(chk.get_mpz_t(), q.get_mpz_t(), qInv.get_mpz_t());
                mpz_mod(chk.get_mpz_t(), chk.get_mpz_t(), p.get_mpz_t());
                if (chk != 1) {
                    throw std::runtime_error("[RSAPS1] qInv is not the modular inverse of q mod p");
                }
            }

            // check if p and q are distinct
            {
            if (p == q)
                throw std::runtime_error("[RSAPS1] p and q must be distinct");
            }

            // check primarlity using simple gmp primarlity test
            //https://gmplib.org/manual/Number-Theoretic-Functions
            {
            if (!mpz_probab_prime_p(p.get_mpz_t(), 25) || !mpz_probab_prime_p(q.get_mpz_t(), 25))
                throw std::runtime_error("[RSAPS1] p or q is not prime");
            }
        }

        // actual cryptographic primitive
        // it uses mpz C-style functions instead overloaded mpz_class operators
        // I think they maybe faster but I'm not 100% sure
        {
            mpz_class s1, s2;
            // s1 = m^dP mod p
            // s2 = m^dQ mod q
            mpz_powm(s1.get_mpz_t(), m.get_mpz_t(), dP.get_mpz_t(), p.get_mpz_t());
            mpz_powm(s2.get_mpz_t(), m.get_mpz_t(), dQ.get_mpz_t(), q.get_mpz_t());

            // most values are reduced mod p before being used

            // diff = s1 - s2
            mpz_class diff;
            mpz_sub(diff.get_mpz_t(), s1.get_mpz_t(), s2.get_mpz_t());
            // diff = diff mod p
            mpz_mod(diff.get_mpz_t(), diff.get_mpz_t(), p.get_mpz_t());


            // h = (s1 - s2) * qInv mod p
            mpz_class h;
            // h = (s1 - s2) * qInv
            mpz_mul(h.get_mpz_t(), diff.get_mpz_t(), qInv.get_mpz_t());
            // h = h mod p
            mpz_mod(h.get_mpz_t(), h.get_mpz_t(), p.get_mpz_t());

            // s = s2 + q*h mod n
            mpz_class s;
            // s = q * h;
            mpz_mul(s.get_mpz_t(), q.get_mpz_t(), h.get_mpz_t());

            // s = s mod n;
            mpz_mod(s.get_mpz_t(), s.get_mpz_t(), n.get_mpz_t());

            // s = s2 + s
            mpz_add(s.get_mpz_t(), s.get_mpz_t(), s2.get_mpz_t());
            // s = s mod n
            mpz_mod(s.get_mpz_t(), s.get_mpz_t(), n.get_mpz_t());

            return s;
        }
    }
    // There are still maybe be some security issues
    // 1. Bellcore/Lenstra Attacks <- I don't even remember what this was about
    // 2. Timing information leaking
    // 3. Private key should be zeroize after being used to prevent leaks UPDATE: NOW IT WILL BE
    // 4. Also additional checks might be added to test see if everything is ok with Private key


    // https://datatracker.ietf.org/doc/html/rfc8017#section-5.2.2
    // actaul cryptographic primitive used for verfictaion
    mpz_class RSAVP1 (const RSAPublicKey& K, const mpz_class& s){
        // get needed values
        const mpz_class& n = K.n();
        const mpz_class& e = K.e();

        // signature representative must be positive and can't be greater than (Otherwise RSA won't work)
        if(s < 0 || s >= n)
            throw std::runtime_error("[RSAVP1] Singnature representative is not between 0 and n-1");

        mpz_class m;
        // m = s ^ e mod n (just like encryption in RSA)
        mpz_powm(m.get_mpz_t(), s.get_mpz_t(), e.get_mpz_t(), n.get_mpz_t());

        return m;
    }

    // https://datatracker.ietf.org/doc/html/rfc8017#section-9.2
    // function that adds some additional DER encoding before signing
    // @M - message to be encoded
    // @emLen -intended length in octets of the encoded message, 
    // return value = encoded message - octet string of length emLen
    std::vector<uint8_t> EMSA_PKCS1_V1_5_ENCODE_sha256(std::vector<uint8_t> const& M, size_t emLen=256){
        using namespace CBZ::SHA;
        // DigestInfo ::= SEQUENCE {
        //   digest_algorithm AlgorithmIdentifier,
        //   digest OCTET STRING
        // }
        AlgorithmIdentifier digest_algorithm(CSRSupportedAlgorithms::sha256);
        //std::vector<uint8_t> digest = encode_der_octet_string(sha256_digest(M));
        std::vector<uint8_t> dig(SHA256::DIGEST_SIZE);
        SHA256::digest(M, dig.data());
        ASN1OctetString dig_os = ASN1OctetString(std::move(dig));
        //std::vector<uint8_t> digestInfo = encode_der_sequence({digest_algorithm.encode(), digest});
        std::vector<uint8_t> digest_info = ASN1Sequence({
            digest_algorithm.to_asn1(),
            dig_os
        }).encode();


        // just required by the standard
        size_t tLen = digest_info.size();
        if(emLen < tLen + 11){
            throw ("[EMSA_PKCS1_V1_5_ENCODE_sha256] Intended encoded message length too short");
        }
        // pad with number 0xFF 
        size_t PSLen = emLen - tLen - 3;
        std::vector<uint8_t> PS(PSLen, 0xFF);

        // EM = 0x00 || 0x01 || PS || 0x00 || DER(digestInfo)
        std::vector<uint8_t> EM(emLen);
        size_t offset = 0;

        EM[offset++] = 0x00;
        EM[offset++] = 0x01;
        std::memcpy(EM.data() + offset, PS.data(), PS.size());
        offset += PS.size();
        EM[offset++] = 0x00;
        std::memcpy(EM.data() + offset, digest_info.data(), digest_info.size());

    
        return EM;
    } 


    // https://datatracker.ietf.org/doc/html/rfc8017#section-8.2.1
    // function that is used to sign a octet string with a given Private Key
    // It is a bit of dispatcher that calls some functions above
    std::vector<uint8_t> RSASSA_PKCS1_V1_5_SIGN(const RSAPrivateKey& K, std::vector<uint8_t> const& M){

        // n is used to calculate k
        const mpz_class& n = K.n();

        // k is the length of signature
        // it is calculated as length in of bytes n from RSA key
        size_t k = (mpz_sizeinbase(n.get_mpz_t(), 2) + 7)/8;


        // encode the message
        std::vector<uint8_t> EM;
        try {
            EM = EMSA_PKCS1_V1_5_ENCODE_sha256(M, k);
        } catch (const std::runtime_error& e) {
            std::throw_with_nested(std::runtime_error("[RSASSA_PKCS1_V1_5_SIGN] Failed to encode message"));
        }


        // convert bytes to message integer representative
        mpz_class m;
        try {
            m = OS2IP(EM);
        } catch( const std::runtime_error& e){
            std::throw_with_nested(std::runtime_error("[RSASSA_PKCS1_V1_5_SIGN] Failed to convert message to integer representative"));
        }


        // get the integer representative of the signature
        mpz_class s;
        try {
            s = RSAPS1(K, m);
        } catch( const std::runtime_error& e){
            std::throw_with_nested(std::runtime_error("[RSASSA_PKCS1_V1_5_SIGN] Failed to sing the message"));
        }


        // convert singnature integer representative to bytes
        std::vector<uint8_t> S;
        try {
            S = I2OSP(s, k);
        } catch( const std::runtime_error& e){
            std::throw_with_nested(std::runtime_error("[RSASSA_PKCS1_V1_5_SIGN] Failed to convert signature to bytes"));
        }

        return S;
    }

    // https://datatracker.ietf.org/doc/html/rfc8017#section-8.2.2
    // function that is used to verify signature bytes using a given Private Key
    // It is a bit of dispatcher that calls some functions above
    bool RSASSA_PKCS1_V1_5_VERIFY(RSAPublicKey const& K, std::vector<uint8_t> const& M, std::vector<uint8_t> const& S){
        // n used to calculate k
        const mpz_class& n = K.n();


        // check if signature has length k
        // it is calculated as length in bytes of n from RSA key
        size_t k = (mpz_sizeinbase(n.get_mpz_t(), 2) + 7) / 8;
        if (k != S.size()){
            throw std::runtime_error("[RSASSA_PKCS1_V1_5_VERIFY] Signature length doesn't match key length");
        }

        // convert signature to integer representative
        mpz_class s;
        try {
            s = OS2IP(S);
        } catch ( const std::runtime_error& e ){
            std::throw_with_nested(std::runtime_error("[RSASSA_PKCS1_V1_5_VERIFY] Failed to convert siganture to integer representative"));
        }

        // apply verfication primitive to signature integer representative
        // to get message integer representative
        mpz_class m;
        try {
            m = RSAVP1(K, s);
        } catch ( const std::runtime_error& e ){
            std::throw_with_nested(std::runtime_error("[RSASSA_PKCS1_V1_5_VERIFY] Failed to convert siganture to integer representative"));
        }

        // convert the message representative to bytes
        std::vector<uint8_t> EM;
        try {
            EM = I2OSP(m, S.size());
        } catch ( const std::runtime_error& e ){
            std::throw_with_nested(std::runtime_error("[RSASSA_PKCS1_V1_5_VERIFY] Failed to message representative to bytes"));
        }

        // apply the EMSA-PKCS1-v1_5 encoding operation to the message M to produce a second encoded message EM2
        std::vector<uint8_t> EM2;
        try {
            EM2 = EMSA_PKCS1_V1_5_ENCODE_sha256(M, S.size());
        } catch ( const std::runtime_error& e ){
            std::throw_with_nested(std::runtime_error("[RSASSA_PKCS1_V1_5_VERIFY] Failed to encode the message bytes"));
        }

        // compare values in constant time
        return CBZ::Security::const_equal(EM, EM2);
    }
}
