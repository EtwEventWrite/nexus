#pragma once

#include "transform.hpp"
#include <cstdint>
#include <vector>
#include <array>

namespace nexus {

class RollingDecrypt {
public:
    RollingDecrypt(uint64_t seed);
    void init_key(uint64_t vip_addr);
    uint8_t decrypt_opcode(const uint8_t* vip);
    uint64_t decrypt_imm(const uint8_t* vip, uint8_t size, uint64_t& out_key);
    uint64_t decrypt_handler_entry(uint64_t encrypted, uint8_t handler_idx);
    uint8_t encrypt_opcode(uint8_t plain, const uint8_t* context);
    uint64_t encrypt_imm(uint64_t plain, uint8_t size, uint64_t& key);
    
    void set_opcode_chain(const std::vector<TransformDesc>& chain);
    void set_imm_chains(const std::array<std::vector<TransformDesc>, 4>& chains);
    void set_handler_xor_key(uint64_t key) { handler_key_ = key; }
    void set_passthrough(bool enable) { passthrough_ = enable; }
    uint64_t get_rolling_key() const { return rolling_key_; }
    void set_rolling_key(uint64_t k) { rolling_key_ = k; }
    
private:
    bool passthrough_ = false;
    TransformEngine engine_;
    uint64_t rolling_key_;
    uint64_t handler_key_;
    
    std::vector<TransformDesc> opcode_chain_;
    std::array<std::vector<TransformDesc>, 4> imm_chains_;
    
    std::vector<TransformDesc> default_opcode_chain();
    std::vector<TransformDesc> default_imm_chain(TransformSize sz);
};

} // namespace nexus
