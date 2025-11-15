#pragma once

#include <bit>

template<std::integral _T>
_T to_bigendian(_T v) {
    if constexpr (std::endian::native == std::endian::little)
        return std::byteswap(v);
    else return v;
}

template<std::integral _T>
_T to_littleendian(_T v) {
    if constexpr (std::endian::native == std::endian::little)
        return v;
    else return std::byteswap(v);
}