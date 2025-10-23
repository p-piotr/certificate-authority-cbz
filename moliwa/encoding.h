#ifndef _encoding
#define _encoding

#include <vector>
#include <unordered_set>
#include <string>
#include <gmpxx.h>
#include <cstdint>
#include "mappings.h"
#include <sstream>
#include "myerror.h"
#include <iostream>


using std::string;
using std::vector;

vector<uint8_t> encode_der_octet_string(const vector<uint8_t> &bytes);
size_t decode_der_octet_string(const vector<uint8_t> &der, size_t &start);

vector<uint8_t> encode_der_length(size_t length);
size_t decode_der_length(const vector<uint8_t> &der, size_t &start);

vector<uint8_t> encode_der_integer(const mpz_class &value);
mpz_class decode_der_integer(const vector<uint8_t> &der, size_t &start);

vector<uint32_t> split_oid(const string &oid);
string serialize_oid(const vector<uint32_t> &oid);

vector<uint8_t> encode_der_oid(const vector<uint32_t> &oid);
vector<uint32_t> decode_der_oid(const vector<uint8_t> &der, size_t &start);

vector<uint8_t> encode_der_string(const string &str, string_t str_type);

vector<uint8_t> encode_der_sequence(const vector<vector<uint8_t>> &elements);
size_t decode_der_sequence(const vector<uint8_t> &der, size_t &start);

vector<uint8_t> encode_der_set(const vector<vector<uint8_t>> &elements);

vector<uint8_t> encode_der_bitstring(const vector<uint8_t>& bytes);

string base64_encode(const vector<uint8_t> &in);
vector<uint8_t> base64_decode(const string &in);

#endif
