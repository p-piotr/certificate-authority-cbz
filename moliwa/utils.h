#ifndef UTILS_H
#define UTILS_H

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

// prints a byte array in hex
// @bytes - refernce to bytes to print
void print_bytes(const vector<uint8_t> &bytes);

template <typename T>
inline void zeroize(vector<T> &vec){
    std::fill(vec.begin(), vec.end(), 0);
    vec.clear();
}
inline void zeroize(string &str){
    std::fill(str.begin(), str.end(), 0);
    str.clear();
}

inline void debug_print(const string &str) {
#ifdef DEBUG
    cout << str << endl;
#endif
}

enum algorithm_t{
    rsaEncryption,
    sha256WithRSAEncryption,
};

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

inline const vector<uint8_t> der_null = {0x05, 0x00};

static const std::unordered_map<string, ASN1_tag> AttributeStringType = {
    {"2.5.4.6",                PRINTABLE_STRING},   // countryName
    {"2.5.4.8",                UTF8_STRING},        // stateOrProvinceName
    {"2.5.4.7",                UTF8_STRING},        // localityName
    {"2.5.4.10",               UTF8_STRING},        // organizationName
    {"2.5.4.11",               UTF8_STRING},        // organizationalUnitName
    {"2.5.4.3",                UTF8_STRING},        // commonName
    {"1.2.840.113549.1.9.1",   IA5_STRING},          // emailAddress
    {"1.2.840.113549.1.9.2",   UTF8_STRING},        // unstructuredName
    {"1.2.840.113549.1.9.7",   UTF8_STRING}         // challengePassword
};

static const std::unordered_map<algorithm_t, string> AlgorithmsToOIDs= {
    {rsaEncryption,             "1.2.840.113549.1.1.1"  },
    {sha256WithRSAEncryption,   "1.2.840.113549.1.1.11" },
};

bool validate_string_type(const string &s, ASN1_tag type);

// This file contains custom exception class that inherits after std::exception
// I'm not gonna pretend that this wasn't vibecoded; I had simply no idea how to do this in code on my own
// Main reason for creating my own error class is that I want to seperate my exceptions from the standard ones
// I also want to use nested exceptions to produce more verbose errors


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
void print_nested(const std::exception& e, int level = 0);

#endif
