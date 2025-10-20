#ifndef _sing_h
#define _sing_h

#include <stdint.h>
#include <vector>
#include "sha256.h"
#include "decode-key.h"
#include "reusable.h"
#include "encoding.h"

using std::vector;
 
vector<uint8_t> RSASSA_PKCS1_V1_5_SIGN(const PrivateKey &K, vector<uint8_t> &M, size_t k);
#endif
