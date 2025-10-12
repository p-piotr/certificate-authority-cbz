#ifndef local_openssl
#define local_openssl

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <vector>
#include <iostream>

using std::string;
using std::vector;

vector<uint8_t> rsa_sha256_sign(const vector<uint8_t> &data, const string &private_key_path);

#endif
