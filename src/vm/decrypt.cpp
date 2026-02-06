#include "vm/decrypt.hpp"
#include <cstring>

namespace nexus {

RollingDecrypt::RollingDecrypt(uint64_t seed) : engine_(seed), rolling_key_(0), handler_key_(0x9E3779B97F4A7C15) {
    set_opcode_chain(default_opcode_chain());
    for (int i = 0; i < 4; ++i) {
        TransformSize sz = static_cast<TransformSize>(1 << i);
        imm_chains_[i] = default_imm_chain(sz);
    }
}

std::vector<TransformDesc> RollingDecrypt::default_opcode_chain() {
    TransformEngine e(0);
    return e.generate_chain(true, TransformSize::S8);
}

std::vector<TransformDesc> RollingDecrypt::default_imm_chain(TransformSize sz) {
    TransformEngine e(static_cast<uint64_t>(sz) * 0x12345);
    return e.generate_chain(false, sz);
}

void RollingDecrypt::init_key(uint64_t vip_addr) {
    rolling_key_ = vip_addr;
}

void RollingDecrypt::set_opcode_chain(const std::vector<TransformDesc>& chain) {
    opcode_chain_ = chain;
}

void RollingDecrypt::set_imm_chains(const std::array<std::vector<TransformDesc>, 4>& chains) {
    imm_chains_ = chains;
}

uint8_t RollingDecrypt::decrypt_opcode(const uint8_t* vip) {
    if (passthrough_) return *vip;
    uint8_t encrypted = *vip;
    uint64_t val = encrypted;
    engine_.decrypt(val, rolling_key_, opcode_chain_);
    return static_cast<uint8_t>(val & 0xFF);
}

uint64_t RollingDecrypt::decrypt_imm(const uint8_t* vip, uint8_t size, uint64_t& out_key) {
    uint64_t val = 0;
    std::memcpy(&val, vip, size);
    if (passthrough_) { out_key = rolling_key_; return val; }
    size_t chain_idx = (size == 1) ? 0 : (size == 2) ? 1 : (size == 4) ? 2 : 3;
    engine_.decrypt(val, rolling_key_, imm_chains_[chain_idx]);
    out_key = rolling_key_;
    return val;
}

uint64_t RollingDecrypt::decrypt_handler_entry(uint64_t encrypted, uint8_t /*handler_idx*/) {
    return encrypted ^ handler_key_;
}

uint8_t RollingDecrypt::encrypt_opcode(uint8_t plain, const uint8_t* /*context*/) {
    uint64_t val = plain;
    engine_.encrypt(val, rolling_key_, opcode_chain_);
    return static_cast<uint8_t>(val & 0xFF);
}

uint64_t RollingDecrypt::encrypt_imm(uint64_t plain, uint8_t size, uint64_t& key) {
    size_t chain_idx = (size == 1) ? 0 : (size == 2) ? 1 : (size == 4) ? 2 : 3;
    return engine_.encrypt(plain, key, imm_chains_[chain_idx]);
}

} // namespace nexus
