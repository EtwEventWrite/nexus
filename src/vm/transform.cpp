#include "vm/transform.hpp"
#include <algorithm>
#include <bit>

namespace nexus {

static uint64_t mask(TransformSize sz) {
    switch (sz) {
        case TransformSize::S8:  return 0xFF;
        case TransformSize::S16: return 0xFFFF;
        case TransformSize::S32: return 0xFFFFFFFF;
        case TransformSize::S64: return 0xFFFFFFFFFFFFFFFF;
    }
    return 0xFFFFFFFFFFFFFFFF;
}

uint64_t TransformEngine::mask_for_size(TransformSize sz) const {
    return mask(sz);
}

uint64_t TransformEngine::do_xor(uint64_t a, uint64_t b, TransformSize sz) {
    return (a ^ b) & mask(sz);
}

uint64_t TransformEngine::do_add(uint64_t a, uint64_t b, TransformSize sz) {
    return (a + b) & mask(sz);
}

uint64_t TransformEngine::do_sub(uint64_t a, uint64_t b, TransformSize sz) {
    return (a - b) & mask(sz);
}

uint64_t TransformEngine::do_rol(uint64_t a, uint64_t b, TransformSize sz) {
    uint64_t m = mask(sz);
    uint64_t bits = (sz == TransformSize::S8) ? 8 : (sz == TransformSize::S16) ? 16 : 
                    (sz == TransformSize::S32) ? 32 : 64;
    b %= bits;
    a &= m;
    return ((a << b) | (a >> (bits - b))) & m;
}

uint64_t TransformEngine::do_ror(uint64_t a, uint64_t b, TransformSize sz) {
    uint64_t m = mask(sz);
    uint64_t bits = (sz == TransformSize::S8) ? 8 : (sz == TransformSize::S16) ? 16 : 
                    (sz == TransformSize::S32) ? 32 : 64;
    b %= bits;
    a &= m;
    return ((a >> b) | (a << (bits - b))) & m;
}

uint64_t TransformEngine::do_neg(uint64_t a, uint64_t b, TransformSize sz) {
    (void)b;
    return (-static_cast<int64_t>(a & mask(sz))) & mask(sz);
}

uint64_t TransformEngine::do_not(uint64_t a, uint64_t b, TransformSize sz) {
    (void)b;
    return (~a) & mask(sz);
}

uint64_t TransformEngine::do_inc(uint64_t a, uint64_t b, TransformSize sz) {
    (void)b;
    return (a + 1) & mask(sz);
}

uint64_t TransformEngine::do_dec(uint64_t a, uint64_t b, TransformSize sz) {
    (void)b;
    return (a - 1) & mask(sz);
}

uint64_t TransformEngine::do_bswap(uint64_t a, uint64_t b, TransformSize sz) {
    (void)b;
    a &= mask(sz);
    if (sz == TransformSize::S16) {
        return ((a >> 8) | (a << 8)) & 0xFFFF;
    }
    if (sz == TransformSize::S32) {
        return (static_cast<uint64_t>(std::byteswap(static_cast<uint32_t>(a)))) & 0xFFFFFFFF;
    }
    if (sz == TransformSize::S64) {
        return std::byteswap(a);
    }
    return a;
}

TransformEngine::TransformEngine(uint64_t seed) : rng_(seed) {}

TransformFn TransformEngine::get_transform(TransformOp op) {
    switch (op) {
        case TransformOp::XOR:   return [](uint64_t a, uint64_t b, TransformSize s) { return do_xor(a,b,s); };
        case TransformOp::ADD:   return [](uint64_t a, uint64_t b, TransformSize s) { return do_add(a,b,s); };
        case TransformOp::SUB:   return [](uint64_t a, uint64_t b, TransformSize s) { return do_sub(a,b,s); };
        case TransformOp::ROL:   return [](uint64_t a, uint64_t b, TransformSize s) { return do_rol(a,b,s); };
        case TransformOp::ROR:   return [](uint64_t a, uint64_t b, TransformSize s) { return do_ror(a,b,s); };
        case TransformOp::NEG:   return [](uint64_t a, uint64_t b, TransformSize s) { return do_neg(a,b,s); };
        case TransformOp::NOT:   return [](uint64_t a, uint64_t b, TransformSize s) { return do_not(a,b,s); };
        case TransformOp::INC:   return [](uint64_t a, uint64_t b, TransformSize s) { return do_inc(a,b,s); };
        case TransformOp::DEC:   return [](uint64_t a, uint64_t b, TransformSize s) { return do_dec(a,b,s); };
        case TransformOp::BSWAP: return [](uint64_t a, uint64_t b, TransformSize s) { return do_bswap(a,b,s); };
        default: return [](uint64_t a, uint64_t, TransformSize s) { return a & mask(s); };
    }
}

TransformFn TransformEngine::get_inverse(TransformOp op) {
    switch (op) {
        case TransformOp::XOR:
        case TransformOp::NOT:
            return get_transform(op);  // Self-inverse
        case TransformOp::ADD: return [](uint64_t a, uint64_t b, TransformSize s) { return do_sub(a,b,s); };
        case TransformOp::SUB: return [](uint64_t a, uint64_t b, TransformSize s) { return do_add(a,b,s); };
        case TransformOp::ROL: return [](uint64_t a, uint64_t b, TransformSize s) { return do_ror(a,b,s); };
        case TransformOp::ROR: return [](uint64_t a, uint64_t b, TransformSize s) { return do_rol(a,b,s); };
        case TransformOp::NEG: return get_transform(op);  // Self-inverse
        case TransformOp::INC: return [](uint64_t a, uint64_t b, TransformSize s) { return do_dec(a,b,s); };
        case TransformOp::DEC: return [](uint64_t a, uint64_t b, TransformSize s) { return do_inc(a,b,s); };
        case TransformOp::BSWAP: return get_transform(op);  // Self-inverse
        default: return [](uint64_t a, uint64_t, TransformSize s) { return a & mask(s); };
    }
}

std::vector<TransformDesc> TransformEngine::generate_chain(bool for_opcode, TransformSize size) {
    std::uniform_int_distribution<int> len_dist(3, 7);
    int chain_len = len_dist(rng_);
    
    static const TransformOp key_ops[] = { TransformOp::XOR, TransformOp::ADD, TransformOp::SUB, TransformOp::ROL, TransformOp::ROR };
    static const TransformOp generic_ops[] = { TransformOp::XOR, TransformOp::ADD, TransformOp::SUB, TransformOp::ROL, TransformOp::ROR,
                                               TransformOp::NEG, TransformOp::NOT, TransformOp::INC, TransformOp::DEC, TransformOp::BSWAP };
    
    std::vector<TransformDesc> chain;
    chain.reserve(chain_len);
    
    std::uniform_int_distribution<size_t> key_idx(0, sizeof(key_ops)/sizeof(key_ops[0]) - 1);
    chain.push_back({ key_ops[key_idx(rng_)], 0, true, size });
    
    for (int i = 1; i < chain_len - 1; ++i) {
        std::uniform_int_distribution<size_t> gen_idx(0, sizeof(generic_ops)/sizeof(generic_ops[0]) - 1);
        TransformOp op = generic_ops[gen_idx(rng_)];
        uint64_t imm = 0;
        if (op == TransformOp::XOR || op == TransformOp::ADD || op == TransformOp::SUB ||
            op == TransformOp::ROL || op == TransformOp::ROR) {
            std::uniform_int_distribution<uint64_t> imm_dist(1, mask(size) - 1);
            imm = imm_dist(rng_);
        }
        chain.push_back({ op, imm, false, size });
    }
    
    chain.push_back({ chain[0].op, 0, true, size });
    
    return chain;
}

uint64_t TransformEngine::decrypt(uint64_t encrypted, uint64_t& rolling_key,
                                  const std::vector<TransformDesc>& chain) {
    uint64_t val = encrypted;
    const size_t n = chain.size();
    if (n < 2) return val;
    
    TransformSize sz = chain[0].size;
    
    auto tf = get_transform(chain[0].op);
    val = tf(val, chain[0].use_key ? rolling_key : chain[0].imm, sz);
    val &= mask_for_size(sz);
    
    for (size_t i = 1; i < n - 1; ++i) {
        tf = get_transform(chain[i].op);
        val = tf(val, chain[i].imm, sz);
        val &= mask_for_size(sz);
    }
    
    tf = get_transform(chain[n-1].op);
    rolling_key = tf(rolling_key, val, sz);
    rolling_key &= mask_for_size(sz);
    
    return val;
}

uint64_t TransformEngine::encrypt(uint64_t plain, uint64_t& rolling_key,
                                  const std::vector<TransformDesc>& chain) {
    uint64_t val = plain;
    const size_t n = chain.size();
    if (n < 2) return val;
    
    const auto sz = chain[0].size;
    const auto m = mask_for_size(sz);
    uint64_t key_after = get_transform(chain[n-1].op)(rolling_key, plain, sz) & m;
    val = plain;
    for (size_t i = n - 2; i >= 1; --i) {
        val = get_inverse(chain[i].op)(val, chain[i].imm, sz) & m;
    }
    
    val = get_inverse(chain[0].op)(val, rolling_key, sz) & m;
    rolling_key = key_after;
    return val;
}

} // namespace nexus
