#include "utils.h"

void print_bytes(const vector<uint8_t> &bytes){
    for(uint8_t byte : bytes)
        printf("%.2X ", byte);
    printf("\n");
}

void der_check_boundry(size_t length, size_t start, size_t curr) {
    if(start + length < curr)
        throw MyError("Pointer went out of bounds when parsing DER" );
}

bool der_check_finish(const vector<uint8_t> &der, const size_t &curr) {
    return (der.size() == curr);
}


// test if string doesn't contain illegal characters; printable_string version
static bool printable_string_validate(const string &s){
    // set of all legal chars in PRINTABLE_STRING
    const std::unordered_set<char> legal = {
        'A', 'a', 'B', 'b', 'C', 'c', 'D', 'd', 'E', 'e',
        'F', 'f', 'G', 'g', 'H', 'h', 'I', 'i', 'J', 'j',
        'K', 'k', 'L', 'l', 'M', 'm', 'N', 'n', 'O', 'o',
        'P', 'p', 'Q', 'q', 'R', 'r', 'S', 's', 'T', 't',
        'U', 'u', 'V', 'v', 'W', 'w', 'X', 'x', 'Y', 'y',
        '0', '1', '2', '3', '4', '5', '6', '7', '8',
        ' ', '\'', '(', ')', '+', ',', '-', '.', '/',
        ':', '?', '='
    };

    // returns false if string contains char not found in set of legal chars
    for (char c : s) {
        if (legal.find(c) == legal.end()) {
            return false; 
        }
    }
    return true;
}


// test if string doesn't contain illegal characters ia5string version
static bool ia5string_validate(const string &s){
    // returns false if string contains a char not found in set of legal chars
    for (unsigned char c : s) {
        if (c > 0x7F) return false;  // Only first 128 ASCII chars allowed
    }
    return true;
}


bool validate_string_type(const string &s, ASN1_tag type){
    switch(type){
        case IA5_STRING:
            return ia5string_validate(s);
            break;
        case PRINTABLE_STRING:
            return printable_string_validate(s);
            break;
        case UTF8_STRING:
            return true;
            break;
        default:
            return false;
            break;
    }
}


// pretty much stolen from here
// https://en.cppreference.com/w/cpp/error/rethrow_if_nested.html
void print_nested(const std::exception& e, int level) {
    std::cerr << std::string(level, ' ')  << e.what() << '\n';
    try {
        std::rethrow_if_nested(e); 
    } catch (const std::exception& nested) {
        print_nested(nested, level + 2);
    } catch (...) {}
}
