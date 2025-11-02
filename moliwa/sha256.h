#ifndef _sha256
#define _sha256

#include <cstdint>
#include <bit>
#include <vector>
#include <iostream>
#include <array>
#include <cstring>
using std::vector;

vector<uint8_t> sha256(const vector<uint8_t> &input);

#endif
