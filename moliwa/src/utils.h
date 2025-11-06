#ifndef UTILS_H
#define UTILS_H

#define DEBUG

// this file contains miscellaneous functions and values used throughout the program
// it allso is the place where includes reside and using statements for common types

#include <fstream>
#include <string>
#include <filesystem>
#include <array>
#include <exception>
#include <iostream>
#include <cstdint>
#include <variant>
#include <iomanip>
#include <assert.h>
#include <utility>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <sstream>
#include <gmpxx.h>

using std::vector;
using std::string;
using std::ifstream;
using std::ofstream;
using std::pair;
using std::variant;
using std::endl;
using std::cout;
using std::cin;
using std::getline;


// used to compare two values in constant time
// @arg1 - first value to be compared
// @arg2 - second value to be compared
// return value: true if equal else false
template <typename T>
inline bool const_equal(vector<T> &arg1, vector<T> &arg2){
    uint8_t diff = 0;

    // if they're of different size we will return false
    // but only after doing the comparsion anyway
    size_t count = std::min(arg1.size(), arg2.size());

    // a xor a = 0
    // so if any of the elements are not equal then diff won't be zero
    for (size_t i = 0; i < count; ++i) {
        diff |= arg1[i] ^ arg2[i];
    }

    // if they are of different size return false
    if(arg1.size() != arg2.size()) { return false; }

    // if diff == 0 return true
    return diff == 0;
}
 
inline bool const_equal(string &arg1, string &arg2){
    uint8_t diff = 0;
    size_t count = std::min(arg1.size(), arg2.size());

    for (size_t i = 0; i < count; ++i) {
        diff |= arg1[i] ^ arg2[i];
    }

    if(arg1.size() != arg2.size()) { return false; }
    return diff == 0;
}

// prints a byte array in hex
// @bytes - reference to bytes to print
inline void print_bytes(const vector<uint8_t> &bytes){
    for(uint8_t byte : bytes)
       printf("%.2X ", byte);
}

// function used to zeroize an object
// it could be overloaded more to zeroize more objects
// @arg - object to be zeroized
template <typename T>
inline void zeroize(vector<T> &arg){
    std::fill(arg.begin(), arg.end(), 0);
    arg.clear();
}
 
inline void zeroize(string &arg){
    std::fill(arg.begin(), arg.end(), 0);
    arg.clear();
}


// used to print a arg if debug is defiend
// it could be overloaded more to print more objects
// could also be improved to accept more arguments and be more flexible
// @arg - object to be printed
inline void debug_print(const string &arg) {
#ifdef DEBUG
    cout << arg ;
#endif
}
inline void debug_print(const vector<uint8_t> &arg) {
#ifdef DEBUG
    print_bytes(arg);
#endif
}
template <typename T>
inline void debug_print(const T &arg) {
#ifdef DEBUG
    cout << arg ;
#endif
}

// enum that stores algorithms handled by the program
enum algorithm_t{
    rsaEncryption,
    sha256WithRSAEncryption,
    sha256
};

// enum that stores tags used in ASN1
// note enum values are exactly the same as ASN1 tags values
enum ASN1_tag {
    INTEGER = 0x02,
    BIT_STRING = 0x03,
    OCTET_STRING = 0x04,
    NULL_TYPE = 0x05,
    OBJECT_IDENTIFIER = 0x06,
    UTF8_STRING = 0x0C,
    SEQUENCE = 0x30,
    SET = 0x31,
    PRINTABLE_STRING = 0x13,
    IA5_STRING = 0x16,
    UTC_TIME = 0x17,
    GENERALIZED_TIME = 0x18,
    ATTRIBUTES_CONSTRUCTED_TYPE = 0xA0
};

// Null value used sometimes in der encoding
inline const vector<uint8_t> der_null = {0x05, 0x00};

// unordered map that maps given OID to it's correspoing string type
// I just based this on what openssl uses, but here's more offical documentation
// https://www.itu.int/rec/T-REC-X.520-201910-I/en
// https://datatracker.ietf.org/doc/html/rfc2985
static const std::unordered_map<string, ASN1_tag> AttributeStringType = {
    {"2.5.4.6",                PRINTABLE_STRING},   // countryName
    {"2.5.4.8",                UTF8_STRING},        // stateOrProvinceName
    {"2.5.4.7",                UTF8_STRING},        // localityName
    {"2.5.4.10",               UTF8_STRING},        // organizationName
    {"2.5.4.11",               UTF8_STRING},        // organizationalUnitName
    {"2.5.4.3",                UTF8_STRING},        // commonName
    {"1.2.840.113549.1.9.1",   IA5_STRING },        // emailAddress
    {"1.2.840.113549.1.9.2",   UTF8_STRING},        // unstructuredName
    {"1.2.840.113549.1.9.7",   UTF8_STRING}         // challengePassword
};

// unordered map that maps algorithm_t types to it's correspoing OID
static const std::unordered_map<algorithm_t, string> AlgorithmsToOIDs= {
    {rsaEncryption,             "1.2.840.113549.1.1.1"  },
    {sha256WithRSAEncryption,   "1.2.840.113549.1.1.11" },
    {sha256,                    "2.16.840.1.101.3.4.2.1"}
};

// used check if a given string doesn't contain illegal chars
// @s - string to be checked
// @type - type of the string (e.g. PRINTABLE_STRING)
bool validate_string_type(const string &s, ASN1_tag type);

// this is my custom error class that inherits from exception
// honestly it was added partially just because I could and also
// to distinguish errors thrown by me from the standard ones
class MyError : public std::exception {
private:
    std::string message;

public:
    explicit MyError(const std::string &msg) : message(msg) {}


    const char* what() const noexcept override {
        return message.c_str();
    }
};

// recursive printer to pretty-print nested exceptions
// when using throw_with_nested
void print_nested(const std::exception& e, int level = 0);

#endif
