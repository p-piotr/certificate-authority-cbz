#pragma once

#include <iostream>
#include <iomanip>
#include <concepts>
#include <span>
#include <stdexcept>
#include <filesystem>

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
            std::cout << std::setw(2) << static_cast<int>(e) << ' ';
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

    inline size_t get_file_size(const char* filepath) {
        return std::filesystem::file_size(std::filesystem::path(filepath));
    }
}