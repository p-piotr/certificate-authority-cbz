#ifndef SING_H
#define SING_H

#include "sha256.h"
#include "PKCSObjects.h"
#include "encoding.h"

// https://datatracker.ietf.org/doc/html/rfc8017#section-8.2.1
// function that is actually used to create the signatures of a given message
// @K - RSA Private Key used to sign the message
// @M - message that will be sign (e.g. CertificationRequestInfo)
// return value: vector of bytes that contains of the signature
vector<uint8_t> RSASSA_PKCS1_V1_5_SIGN(const PKCS::RSAPrivateKey &K, const vector<uint8_t> &M);

// https://datatracker.ietf.org/doc/html/rfc8017#section-8.2.2
// function that is used to check if signature is correct
// @K - RSA Public Key part used to verify the signature (Must be match Private Key used when signing)
// @M - message to be verified (e.g. CertificationRequestInfo)
// @S - signature of the message
// return value: true if signature is correct else false
bool RSASSA_PKCS1_V1_5_VERIFY(const PKCS::RSAPublicKey &K, const vector<uint8_t> &M, const vector<uint8_t> &S);

#endif
