#pragma once

#include <cstdint>
#include <functional>
#include <random>
#include <array>

namespace nexus {

enum class TransformOp : uint8_t {
    XOR, ADD, SUB, MUL,
    ROL, ROR, ROL_CARRY, ROR_CARRY,
    NEG, NOT, INC, DEC,
    BSWAP, REV16, REV32,
    TRANSFORM_COUNT
};

enum class TransformSize : uint8_t { S8 = 1, S16 = 2, S32 = 4, S64 = 8 };

using TransformFn = std::function<uint64_t(uint64_t a, uint64_t b, TransformSize sz)>;

struct TransformDesc {
    TransformOp op;
    uint64_t imm;
    bool use_key;
    TransformSize size;
};

class TransformEngine {
public:
    TransformEngine(uint64_t seed = 0);
    std::vector<TransformDesc> generate_chain(bool for_opcode, TransformSize size);
    uint64_t decrypt(uint64_t encrypted, uint64_t& rolling_key,
                     const std::vector<TransformDesc>& chain);
    uint64_t encrypt(uint64_t plain, uint64_t& rolling_key,
                     const std::vector<TransformDesc>& chain);
    static TransformFn get_transform(TransformOp op);
    static TransformFn get_inverse(TransformOp op);

private:
    std::mt19937_64 rng_;
    
    static uint64_t do_xor(uint64_t a, uint64_t b, TransformSize sz);
    static uint64_t do_add(uint64_t a, uint64_t b, TransformSize sz);
    static uint64_t do_sub(uint64_t a, uint64_t b, TransformSize sz);
    static uint64_t do_rol(uint64_t a, uint64_t b, TransformSize sz);
    static uint64_t do_ror(uint64_t a, uint64_t b, TransformSize sz);
    static uint64_t do_neg(uint64_t a, uint64_t b, TransformSize sz);
    static uint64_t do_not(uint64_t a, uint64_t b, TransformSize sz);
    static uint64_t do_inc(uint64_t a, uint64_t b, TransformSize sz);
    static uint64_t do_dec(uint64_t a, uint64_t b, TransformSize sz);
    static uint64_t do_bswap(uint64_t a, uint64_t b, TransformSize sz);
    
    uint64_t mask_for_size(TransformSize sz) const;
};

} // namespace nexus
