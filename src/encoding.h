#ifndef ENCODE_H
#define ENCODE_H

#include "utils.h"
#include "asn1/asn1.h"

// using CBZ::ASN1::ASN1Tag = CBZ::ASN1::ASN1Tag;

// this contains function releted to encoding primitive ASN.1 types into DER
// Those functions are then used in to simplify encoding entire ASN.1 / PKCS objects

// Performance considerations:
// These functions aren't exactly efficient as there's a lot of copying between vectors
// It may be better to:
// option a: store values in deque to which you can easily append at the start and at the end
// option b: start with a big vector and go outward from the middle, using shrink_to_fit() at the end
// As of now It works I may change it later tho


// @value - mpz_class integer to be enocoded
// return value: vector of encoded bytes
vector<uint8_t> encode_der_integer(const mpz_class& value);

// @oid - string representation of OID e.g. "1.2.3.4.5"
// return value: vector of encoded bytes
vector<uint8_t> encode_der_oid(const string& oid);

// @str - string to be encoded
// @str_type - which type of strings should be used (e.g. utf8-string, printable-string)
// return value: vector of encoded bytes
// it also includes checks to test if strings doesn't contain bytes not encodeable by given string type
vector<uint8_t> encode_der_string(const string& str, CBZ::ASN1::ASN1Tag str_type);

// @elements - vector of vectors; each inner vector contains already DER-encoded element of the sequence
// return value: vector of encoded bytes
vector<uint8_t> encode_der_sequence(const vector<vector<uint8_t>>& elements);

// @elements - vector of vectors; each inner vector contains already DER-encoded element of the sequence
// return value: vector of encoded bytes
// NOTE: it will sort the elements vector
// Usually the elements vector will be created for the purpose of using this function anyway
vector<uint8_t> encode_der_set(vector<vector<uint8_t>>& elements);

// @bits - vector that contains bytes to encode
// @unused - how many bits in the first byte are unsued; in range 0 to 7
// by default we assume that all bits are used
// return value: vector of encoded bytes
vector<uint8_t> encode_der_bitstring(const vector<uint8_t>& bits, uint8_t unused = 0);

// @bytes- vector that contains bytes to encode
// return value: vector of encoded bytes
vector<uint8_t> encode_der_octet_string(const vector<uint8_t>& bytes);

// @in - bytes to encode
// return value: base64 enocoded string
// It was stolen from the internet; So I'm not sure what it does but quite a bit of bit magic
// Note that if don't want it to encode whitespace you should remove it before calling the function
string base64_encode(const vector<uint8_t>& in);

// @in - bytes to encode
// @tag - tag with which those bytes should be encoded
// return value: vector of encoded bytes
// This function was created because for PKCS#10 force me to
// For reasons that elude me Attributes field in certificationRequestInfo uses context-specific tag 0xA0
// Therefore I decided to create function that encodes those non-universal types 
// Function is almost identical to encode_der_octet_string but encodes tag of choice
vector<uint8_t> encode_der_non_universal(const vector<uint8_t>& bytes, CBZ::ASN1::ASN1Tag tag);

#endif
