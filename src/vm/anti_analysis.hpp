#pragma once

#include <cstdint>

namespace nexus {

namespace opaque {

inline bool always_true_square(int64_t x) {
    return (x * x) >= 0;
}

inline bool always_false_impossible(int64_t x) {
    (void)x;
    return false;
}

inline uint64_t opaque_constant(uint64_t seed) {
    uint64_t v = seed;
    for (int i = 0; i < 5; ++i) {
        v = (v & 1) ? (v * 3 + 1) : (v >> 1);
    }
    return v;
}

} // namespace opaque

namespace anti_debug {

inline bool timing_anomaly() {
    return false;
}

inline uint64_t checksum(const void* data, size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    uint64_t h = 0x9e3779b97f4a7c15ULL;
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 0xbf58476d1ce4e5b9ULL;
        h ^= h >> 32;
    }
    return h;
}

} // namespace anti_debug

} // namespace nexus
