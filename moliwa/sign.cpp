#include "sign.h"

// https://datatracker.ietf.org/doc/html/rfc8017#section-4.2
static mpz_class OS2IP(vector<uint8_t> &in){
    mpz_class out = 0;
    for(uint8_t byte : in){
        out <<= 8;
        out += byte;
    }
    return out;
}

// https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
static vector<uint8_t> I2OSP(const mpz_class &in, size_t xLen){
    if (in < 0) {
        throw std::invalid_argument("I2OSP: integer must be nonnegative");
    }

    mpz_class max_val = 1;
    max_val <<= 8 * xLen;
    if (in >= max_val) {
        throw std::overflow_error("I2OSP: integer too large");
    }

    
    vector<uint8_t> out(xLen, 0);
    mpz_class temp = in;
    for (int i = xLen - 1; i >= 0; --i) {
        mpz_class temp_byte = (temp & 0xFF);
        out[i] = temp_byte.get_ui();
        temp >>= 8;
    }

    return out;
}

// https://datatracker.ietf.org/doc/html/rfc8017#section-5.2.1
// Note: Using method b
// Note: assuming that r_i, d_i, t_i are not present
//
// Note: according to my best friend there are several security issues here:
// 1. Bellcore/Lenstra Attacks - Validate the signature after computing it
// 2. Timing information leaking - RSA blinding should be added
// 3. Memory leaks of private key data can happen, memory should be cleared explicitly - this applies to PrivateKey struct as well
// 4. Also additional checks could be added to test see if everything is as it should be with private key
static mpz_class RSAPS1(const PrivateKey &K, mpz_class &m){
    if (m < 0 || m >= K.n) {
        throw std::domain_error("message representative out of range");
    }

    // Check if q * qInv = 1 mod p
    {
        mpz_class chk;
        mpz_mul(chk.get_mpz_t(), K.q.get_mpz_t(), K.qInv.get_mpz_t());
        mpz_mod(chk.get_mpz_t(), chk.get_mpz_t(), K.p.get_mpz_t());
        if (chk != 1) {
            throw std::runtime_error("qInv is not the modular inverse of q mod p");
        }
    }


    mpz_class s1, s2;
    // s1 = m^dP mod p, s2 = m^dQ mod q
    mpz_powm(s1.get_mpz_t(), m.get_mpz_t(), K.dP.get_mpz_t(), K.p.get_mpz_t());
    mpz_powm(s2.get_mpz_t(), m.get_mpz_t(), K.dQ.get_mpz_t(), K.q.get_mpz_t());

    // h = (s1 - s2) * qInv mod p
    // Note: we will reduce everything mod p first
    mpz_class diff;
    mpz_sub(diff.get_mpz_t(), s1.get_mpz_t(), s2.get_mpz_t());
    mpz_mod(diff.get_mpz_t(), diff.get_mpz_t(), K.p.get_mpz_t());

    mpz_class qInv_mod;
    mpz_mod(qInv_mod.get_mpz_t(), K.qInv.get_mpz_t(), K.p.get_mpz_t());

    mpz_class h;
    mpz_mul(h.get_mpz_t(), diff.get_mpz_t(), qInv_mod.get_mpz_t());
    mpz_mod(h.get_mpz_t(), h.get_mpz_t(), K.p.get_mpz_t());

    // s = s2 + q*h mod n
    mpz_class s;
    mpz_mul(s.get_mpz_t(), K.q.get_mpz_t(), h.get_mpz_t());
    mpz_mod(s.get_mpz_t(), s.get_mpz_t(), K.n.get_mpz_t());

    mpz_add(s.get_mpz_t(), s.get_mpz_t(), s2.get_mpz_t());
    mpz_mod(s.get_mpz_t(), s.get_mpz_t(), K.n.get_mpz_t());

    return s;
}

// https://datatracker.ietf.org/doc/html/rfc8017#section-9.2
static vector<uint8_t> EMSA_PKCS1_V1_5_ENCODE_sha256(const vector<uint8_t> &M, size_t emLen=256){
    AlgorithmIdentifier digestAlgorithm("2.16.840.1.101.3.4.2.1");
    vector<uint8_t> digest = encode_der_octet_string(sha256(M));
    vector<uint8_t> digestInfo = encode_der_sequence({digestAlgorithm.encode(), digest});
    #ifdef DEBUG
    print_bytes(digestInfo);
    #endif

    size_t tLen = digestInfo.size();
    if(emLen < tLen + 11){
        throw std::invalid_argument("intended encoded message length too short");
    }
    size_t PSLen = emLen - tLen - 3;
    vector<uint8_t> PS(PSLen, 0xFF);

    vector<uint8_t> EM;
    EM.reserve(emLen);
    EM.push_back(0x00);
    EM.push_back(0x01);
    EM.insert(EM.end(), PS.begin(), PS.end());
    EM.push_back(0x00);
    EM.insert(EM.end(), digestInfo.begin(), digestInfo.end());

    #ifdef DEBUG
    print_bytes(EM);
    #endif
    return EM;
} 

static size_t k_for_key(const mpz_class &n){
    size_t bits = mpz_sizeinbase(n.get_mpz_t(), 2);
    return (bits + 7) / 8;
}

// https://datatracker.ietf.org/doc/html/rfc8017#section-8.2.1
vector<uint8_t> RSASSA_PKCS1_V1_5_SIGN(const PrivateKey &K, vector<uint8_t> &M, size_t k){
    if (k == 0)
        k = k_for_key(K.n);
    vector<uint8_t> EM = EMSA_PKCS1_V1_5_ENCODE_sha256(M, k);
    mpz_class m = OS2IP(EM);
    mpz_class s = RSAPS1(K, m);
    return I2OSP(s, k);
}


