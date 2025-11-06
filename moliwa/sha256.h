#ifndef SHA256_H
#define SHA256_H

#include "utils.h"

// really simple implementation of sha256 based on pseudocode from wikipedia

// @input - bytes to be hashed
// return value: digest - techinally it's always the same length (256 bits)
// so it could be array instead of vector but program uses vector everywhere
// so no point in changing that just for this function
vector<uint8_t> sha256(const vector<uint8_t> &input);

#endif
