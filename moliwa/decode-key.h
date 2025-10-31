#ifndef decode_key_h
#define decode_key_h

#include "reusable.h"
#include <gmpxx.h>
#include <fstream>
#include <iostream>
#include "encoding.h"
#include "decoding.h"
#include "myerror.h"

using std::cerr;
using std::cout;
using std::ifstream;
using std::endl;

struct PrivateKey {
    int version;
    mpz_class n, e, d, p, q, dP, dQ, qInv;
    PrivateKey() : version(0), n(0), e(0), d(0), p(0), q(0), dP(0), dQ(0), qInv(0) {}
    PrivateKey (
    mpz_class &n_,
    mpz_class &e_,
    mpz_class &d_,
    mpz_class &p_,
    mpz_class &q_,
    mpz_class &dP_,
    mpz_class &dQ_,
    mpz_class &qInv_,
    size_t version_ = 0
    ) : version(version_), n(n_), e(e_), d(d_), p(p_), q(q_), dP(dP_), dQ(dQ_), qInv(qInv_) {}



    vector<uint8_t> encode() const {
            return encode_der_sequence({
                encode_der_integer(version),
                encode_der_integer(n),
                encode_der_integer(e),
                encode_der_integer(d),
                encode_der_integer(p),
                encode_der_integer(q),
                encode_der_integer(dP),
                encode_der_integer(dQ),
                encode_der_integer(qInv),
            });
    }
};

class PrivateKeyInfo {
    size_t version;
    AlgorithmIdentifier privateKeyAlgorithm;
    PrivateKey privateKey;
public:
    PrivateKeyInfo(const AlgorithmIdentifier &privateKeyAlgorithm_, const PrivateKey &privateKey_, int version_ = 0) : version(version_), privateKeyAlgorithm(privateKeyAlgorithm_), privateKey(privateKey_) {}

    PrivateKeyInfo (
    mpz_class &n_,
    mpz_class &e_,
    mpz_class &d_,
    mpz_class &p_,
    mpz_class &q_,
    mpz_class &dP_,
    mpz_class &dQ_,
    mpz_class &qInv_,
    size_t version_ = 0
    ) : privateKeyAlgorithm("1.2.840.113549.1.1.1"), privateKey(n_, e_, d_, p_, q_, dP_, dQ_, qInv_, 0), version(version_) {}

    const PrivateKey& getPrivateKeyReference() const { return  privateKey; };

};

PrivateKey parse_der_privateKey(const vector<uint8_t> &der, size_t &start);
PrivateKeyInfo parse_der(const vector<uint8_t> &der);
PrivateKeyInfo read_from_file(const string &path); 

#endif
