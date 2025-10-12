#ifndef _encoding
#define _encoding

#include <vector>
#include <string>
#include <gmpxx.h>
#include <cinttypes>
#include "mappings.h"


using std::string;
using std::vector;

vector<uint8_t> encode_der_length(size_t length);
vector<uint8_t> encode_der_integer(const mpz_class &value);
vector<uint8_t> encode_der_oid(const vector<uint32_t> &oid);
vector<uint8_t> encode_der_string(const string &str, string_t str_type);
vector<uint32_t> split_oid(const string &oid);
string serialize_oid(const vector<uint32_t> &oid);
vector<uint8_t> encode_der_sequence(const vector<vector<uint8_t>> &elements);
vector<uint8_t> encode_der_set(const vector<vector<uint8_t>> &elements);
vector<uint8_t> encode_der_bitstring(const vector<uint8_t>& bytes);
string base64_encode(const vector<uint8_t> &in);

#endif
