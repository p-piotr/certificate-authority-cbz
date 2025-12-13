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


// ----------------------------------------------------------------------------------------------------

// enum that stores algorithms handled by the program
enum algorithm_t{
    rsaEncryption,
    sha256WithRSAEncryption,
    sha256
};

// Null value used sometimes in der encoding
inline const vector<uint8_t> der_null = {0x05, 0x00};

// unordered map that maps algorithm_t types to it's correspoing OID
static const std::unordered_map<algorithm_t, string> AlgorithmsToOIDs= {
    {rsaEncryption,             "1.2.840.113549.1.1.1"  },
    {sha256WithRSAEncryption,   "1.2.840.113549.1.1.11" },
    {sha256,                    "2.16.840.1.101.3.4.2.1"}
};

#endif
