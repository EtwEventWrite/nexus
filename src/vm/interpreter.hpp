#pragma once

#include "vm/bytecode.hpp"
#include "vm/decrypt.hpp"
#include <cstdint>
#include <array>
#include <vector>

namespace nexus {

struct VMContext {
    std::array<uint64_t, SCRATCH_COUNT> scratch;
    uint64_t* vsp;
    uint64_t* stack_base;
    size_t stack_size;
    uint64_t module_base;
};

class Interpreter {
public:
    Interpreter();
    void execute(const uint8_t*& vip, VMContext& ctx);
    
    void set_decryptor(RollingDecrypt* d) { decrypt_ = d; }
    void set_handler_table(const std::vector<void*>& table) { handlers_ = table; }

private:
    RollingDecrypt* decrypt_ = nullptr;
    std::vector<void*> handlers_;

    void dispatch(const uint8_t*& vip, VMContext& ctx, uint8_t opcode);
    void op_nop(const uint8_t*& vip, VMContext& ctx);
    void op_push_i64(const uint8_t*& vip, VMContext& ctx, uint8_t size);
    void op_pop(const uint8_t*& vip, VMContext& ctx);
    void op_lreg(const uint8_t*& vip, VMContext& ctx, uint8_t size);
    void op_sreg(const uint8_t*& vip, VMContext& ctx, uint8_t size);
    void op_add(const uint8_t*& vip, VMContext& ctx, uint8_t size);
    void op_sub(const uint8_t*& vip, VMContext& ctx, uint8_t size);
    void op_mul(const uint8_t*& vip, VMContext& ctx, uint8_t size);
    void op_and(const uint8_t*& vip, VMContext& ctx, uint8_t size);
    void op_or(const uint8_t*& vip, VMContext& ctx, uint8_t size);
    void op_xor(const uint8_t*& vip, VMContext& ctx, uint8_t size);
    void op_read(const uint8_t*& vip, VMContext& ctx, uint8_t size);
    void op_write(const uint8_t*& vip, VMContext& ctx, uint8_t size);
    void op_jmp(const uint8_t*& vip, VMContext& ctx);
    void op_ret(const uint8_t*& vip, VMContext& ctx);
    void op_exit(const uint8_t*& vip, VMContext& ctx);
    
    uint64_t read_imm(const uint8_t*& vip, uint8_t size);
};

} // namespace nexus
