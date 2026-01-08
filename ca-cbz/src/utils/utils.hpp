#pragma once

#include <iostream>
#include <iomanip>
#include <concepts>
#include <span>
#include <stdexcept>
#include <filesystem>
#include <unordered_map>
#include <utility>

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

    // performs a universal throw, that is
    // if called from inside 'catch' clause -> calls std::throw_with_nested
    // otherwise -> casual 'throw'
    template <typename _E>
    concept Exception = std::derived_from<_E, std::exception>;

    template <Exception _E>
    inline void universal_throw(_E e) {
        if (std::current_exception()) {
            std::throw_with_nested(std::move(e));
        } else {
            throw e;
        }
    }

    inline void universal_throw(std::string message) {
        auto e = std::runtime_error(std::move(message));
        universal_throw(std::move(e));
    }

    // dumb object that acts like a bidirectional hashmap
    // used when encoding/decoding OIDs
    template <typename _K, typename _V>
    class BidirectionalMap {
    private:
        std::unordered_map<_K, _V> _forward_map;
        std::unordered_map<_V, _K> _reverse_map;

    public:
        BidirectionalMap(std::initializer_list<std::pair<_K, _V>> il) {
            for (const std::pair<_K, _V>& entry : il) {
                if (_forward_map.count(entry.first)) {
                    throw std::runtime_error("[BidirectionalMap::BidirectionalMap] Forward key already exists");
                }
                if (_reverse_map.count(entry.second)) {
                    throw std::runtime_error("[BidirectionalMap::BidiretionalMap] Forward value already exists");
                }
                _forward_map[entry.first] = entry.second;
                _reverse_map[entry.second] = entry.first;
            }
        }

        _V get_by_key(const _K& key) const {
            return _forward_map.at(key);
        }

        // alias to get_by_key
        _V at(const _K& key) const {
            return get_by_key(key);
        }

        _K get_by_value(const _V& value) const {
            return _reverse_map.at(value);
        }

        // functions below needed to be implemented in order not to break other parts of code which
        // rely on searching through the dictionary

        auto find(const _K& key) const {
            return _forward_map.find(key);
        }

        auto begin() const {
            return _forward_map.begin();
        }

        auto end() const {
            return _forward_map.end();
        }

        // functions below are very same as those above, but acting on _reverse_map, so backwards

        auto reverse_find(const _V& value) const {
            return _reverse_map.find(value);
        }

        // don't confuse with rbegin()! it's a totally different thing
        auto reverse_begin() const {
            return _reverse_map.begin();
        }

        // the same - don't confuse with rend()!
        auto reverse_end() const {
            return _reverse_map.end();
        }
    };

    // Compares header at the beginning of given Base64 buffer
    // with another specified header
    inline bool compare_header(const std::string& b64, const std::string& h) {
        if (b64.size() < h.size())
            return false;

        int r = std::memcmp(
            b64.data(),
            h.data(),
            h.size()
        );

        if (r == 0)
            return true;
        else return false;
    }

    // Compares footer at the end of given Base64 buffer
    // with another specifier footer
    inline bool compare_footer(const std::string& b64, const std::string& f) {
        if (b64.size() < f.size())
            return false;

        int r = std::memcmp(
            b64.data() + (b64.size() - f.size()),
            f.data(),
            f.size()
        );

        if (r == 0)
            return true;
        else return false;
    }

}