#ifndef DECODE_H
#define DECODE_H

#include "myerror.h"
#include "utils.h"



// NOTE: These functions were created with assumptions that DER bytes have been read into some shared buffer
// Each function takes the @offset parameter that indicates where in this shared buffer they should start decoding
// Each function modifies the @offset so that when function returns, @offset now points to the next byte to decode

// @der_buffer - shared DER buffer to read bytes from
// @offset - where in the buffer should the function start decoding
// return value: decoded integer as mpz_class 
mpz_class decode_der_integer(const vector<uint8_t> &der_buffer, size_t &offset);

// @der_buffer - shared DER buffer to read bytes from
// @offset - where in the buffer should the function start decoding
// return value: decoded OID as string e.g. "1.2.3.4.5"
string decode_der_oid(const vector<uint8_t> &der_buffer, size_t &offset);

// @der_buffer - shared DER buffer to read bytes from
// @offset - where in the buffer should the function start decoding
// return value: length of the sequence
// Note that the bytes that follow will have to be decoded by something else
// as sequence can hold values of different type
size_t decode_der_sequence(const vector<uint8_t> &der_buffer, size_t &start);

// @der_buffer - shared DER buffer to read bytes from
// @offset - where in the buffer should the function start decoding
// return value: length of the octet_string
// Note: that the bytes that follow will have to be decoded by something else
// as those bytes can meaning can change based on context
size_t decode_der_octet_string(const vector<uint8_t> &der_buffer, size_t &start);

// @in - string contain base64 encoded message
// @out - vector into which decoded bytes will be stored
// I decided to use buffer passed by reference as I will have to base64_decode PrivateKey file
void base64_decode(const string &in, vector<uint8_t> &out);

#endif
