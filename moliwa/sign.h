#ifndef SING_H
#define SING_H

#include <stdint.h>
#include <vector>
#include "sha256.h"
#include "PKCSObjects.h"
#include "encoding.h"

using std::vector;
 
vector<uint8_t> RSASSA_PKCS1_V1_5_SIGN(const PKCS::RSAPrivateKey &K, const vector<uint8_t> &M);
bool RSASSA_PKCS1_V1_5_VERIFY(const PKCS::RSAPublicKey &K, const vector<uint8_t> &M, const vector<uint8_t> &S);
#endif
