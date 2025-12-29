#pragma once

#include <iostream>
#include <iomanip>
#include <concepts>
#include <span>
#include <stdexcept>
#include "asn1/asn1.h"

namespace CBZ::Utils {

    template <typename _R>
    concept ContiguousRange = std::ranges::contiguous_range<_R>;

    template <ContiguousRange _R>
    inline void print_bytes(_R const& r) {
        const auto s = std::span{r};
        std::cout 
            << std::uppercase << std::hex 
            << std::setfill('0');
        for (const auto e : s) {
            std::cout << std::setw(2) << 
            static_cast<unsigned int>(e) << ' ';
        }
        std::cout
            << std::nouppercase << std::dec
            << std::setfill(' ') << std::endl;
    }

    // used to pretty print nested exceptions
    // pretty much stolen from here
    // https://en.cppreference.com/w/cpp/error/rethrow_if_nested.html
    inline void print_nested(std::exception const& e, int level = 0) {
        std::cerr << std::string(level, ' ')  << e.what() << '\n';
        try {
            std::rethrow_if_nested(e); 
        } catch (const std::exception& nested) {
            print_nested(nested, level + 2);
        } catch (...) {}
    }

    // test if string doesn't contain illegal characters; printable_string version
    static bool validate_printable_string(std::string const& s) {
        auto _check = [](char c) {
            if (c >= 0x41 && c <= 0x5A)
                return true;
            if (c >= 0x61 && c <= 0x7A)
                return true;
            if (c >= 0x30 && c <= 0x39)
                return true;
            if (c >= 0x27 && c <= 0x29)
                return true;
            if (c >= 0x2B && c <= 0x2F)
                return true;
            if (c == 0x20 || c == 0x3A || c == 0x3D || c == 0x3F)
                return true;
            return false;
        };

        for (char c : s) {
            if (!_check(c))
                return false;
        }
        return true;
    }


    // test if string doesn't contain illegal characters ia5string version
    static bool ia5string_validate(std::string const& s){
        // returns false if string contains a char not found in set of legal chars
        for (unsigned char c : s)
            if (c > 0x7F) return false;  // Only first 128 ASCII chars allowed

        return true;
    }


    // dispatcher function that calls appropriate validating function based on tag (only 2 functions as of now)
    inline bool validate_string_type(std::string const& s, CBZ::ASN1::ASN1Tag type){
        using namespace ASN1;

        switch(type){
            case IA5_STRING:
                return ia5string_validate(s);
            case PRINTABLE_STRING:
                return validate_printable_string(s);
            case UTF8_STRING:
                return true;
            default:
                return false;
        }
    }
}
