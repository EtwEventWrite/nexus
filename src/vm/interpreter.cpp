#include "vm/interpreter.hpp"
#include <cstring>
#include <stdexcept>

namespace nexus {

Interpreter::Interpreter() = default;

void Interpreter::execute(const uint8_t*& vip, VMContext& ctx) {
    if (!decrypt_) return;
    
    decrypt_->init_key(reinterpret_cast<uint64_t>(vip));
    
    while (true) {
        uint8_t opcode = decrypt_->decrypt_opcode(vip);
        vip++;
        
        if (opcode == static_cast<uint8_t>(Opcode::EXIT)) {
            op_exit(vip, ctx);
            return;
        }
        
        dispatch(vip, ctx, opcode);
    }
}

void Interpreter::dispatch(const uint8_t*& vip, VMContext& ctx, uint8_t opcode) {
    switch (static_cast<Opcode>(opcode)) {
        case Opcode::NOP:
            break;
        case Opcode::PUSH_I8:  op_push_i64(vip, ctx, 1); break;
        case Opcode::PUSH_I16: op_push_i64(vip, ctx, 2); break;
        case Opcode::PUSH_I32: op_push_i64(vip, ctx, 4); break;
        case Opcode::PUSH_I64: op_push_i64(vip, ctx, 8); break;
        case Opcode::POP:      op_pop(vip, ctx); break;
        case Opcode::LREG8:    op_lreg(vip, ctx, 1); break;
        case Opcode::LREG16:   op_lreg(vip, ctx, 2); break;
        case Opcode::LREG32:   op_lreg(vip, ctx, 4); break;
        case Opcode::LREG64:   op_lreg(vip, ctx, 8); break;
        case Opcode::SREG8:    op_sreg(vip, ctx, 1); break;
        case Opcode::SREG16:   op_sreg(vip, ctx, 2); break;
        case Opcode::SREG32:   op_sreg(vip, ctx, 4); break;
        case Opcode::SREG64:   op_sreg(vip, ctx, 8); break;
        case Opcode::ADD8:  op_add(vip, ctx, 1); break;
        case Opcode::ADD16: op_add(vip, ctx, 2); break;
        case Opcode::ADD32: op_add(vip, ctx, 4); break;
        case Opcode::ADD64: op_add(vip, ctx, 8); break;
        case Opcode::SUB8:  op_sub(vip, ctx, 1); break;
        case Opcode::SUB16: op_sub(vip, ctx, 2); break;
        case Opcode::SUB32: op_sub(vip, ctx, 4); break;
        case Opcode::SUB64: op_sub(vip, ctx, 8); break;
        case Opcode::MUL8:  op_mul(vip, ctx, 1); break;
        case Opcode::MUL16: op_mul(vip, ctx, 2); break;
        case Opcode::MUL32: op_mul(vip, ctx, 4); break;
        case Opcode::MUL64: op_mul(vip, ctx, 8); break;
        case Opcode::AND8:  op_and(vip, ctx, 1); break;
        case Opcode::AND16: op_and(vip, ctx, 2); break;
        case Opcode::AND32: op_and(vip, ctx, 4); break;
        case Opcode::AND64: op_and(vip, ctx, 8); break;
        case Opcode::OR8:   op_or(vip, ctx, 1); break;
        case Opcode::OR16:  op_or(vip, ctx, 2); break;
        case Opcode::OR32:  op_or(vip, ctx, 4); break;
        case Opcode::OR64:  op_or(vip, ctx, 8); break;
        case Opcode::XOR8:  op_xor(vip, ctx, 1); break;
        case Opcode::XOR16: op_xor(vip, ctx, 2); break;
        case Opcode::XOR32: op_xor(vip, ctx, 4); break;
        case Opcode::XOR64: op_xor(vip, ctx, 8); break;
        case Opcode::READ8:  op_read(vip, ctx, 1); break;
        case Opcode::READ16: op_read(vip, ctx, 2); break;
        case Opcode::READ32: op_read(vip, ctx, 4); break;
        case Opcode::READ64: op_read(vip, ctx, 8); break;
        case Opcode::WRITE8:  op_write(vip, ctx, 1); break;
        case Opcode::WRITE16: op_write(vip, ctx, 2); break;
        case Opcode::WRITE32: op_write(vip, ctx, 4); break;
        case Opcode::WRITE64: op_write(vip, ctx, 8); break;
        case Opcode::JMP:     op_jmp(vip, ctx); break;
        case Opcode::RET:     op_ret(vip, ctx); break;
        case Opcode::EXIT:    op_exit(vip, ctx); return;
        default:
            break;
    }
}

uint64_t Interpreter::read_imm(const uint8_t*& vip, uint8_t size) {
    uint64_t key;
    uint64_t val = decrypt_->decrypt_imm(vip, size, key);
    vip += size;
    return val;
}

void Interpreter::op_push_i64(const uint8_t*& vip, VMContext& ctx, uint8_t size) {
    uint64_t imm = read_imm(vip, size);
    ctx.vsp--;
    *ctx.vsp = imm;
}

void Interpreter::op_pop(const uint8_t*& vip, VMContext& ctx) {
    (void)vip;
    ctx.vsp++;
}

void Interpreter::op_lreg(const uint8_t*& vip, VMContext& ctx, uint8_t size) {
    uint64_t tmp;
    uint8_t reg_idx = static_cast<uint8_t>(decrypt_->decrypt_imm(vip, 1, tmp));
    vip += 1;
    uint64_t val = 0;
    if (reg_idx < SCRATCH_COUNT) {
        val = ctx.scratch[reg_idx] & ((1ULL << (size * 8)) - 1);
    }
    ctx.vsp--;
    *ctx.vsp = val;
}

void Interpreter::op_sreg(const uint8_t*& vip, VMContext& ctx, uint8_t size) {
    uint64_t tmp;
    uint8_t reg_idx = static_cast<uint8_t>(decrypt_->decrypt_imm(vip, 1, tmp));
    vip += 1;
    uint64_t val = *ctx.vsp++;
    uint64_t mask = (size == 8) ? 0xFFFFFFFFFFFFFFFF : (1ULL << (size * 8)) - 1;
    if (reg_idx < SCRATCH_COUNT) {
        ctx.scratch[reg_idx] = (ctx.scratch[reg_idx] & ~mask) | (val & mask);
    }
}

void Interpreter::op_add(const uint8_t*& vip, VMContext& ctx, uint8_t size) {
    (void)vip;
    uint64_t b = *ctx.vsp++;
    uint64_t a = *ctx.vsp;
    uint64_t mask = (size == 8) ? 0xFFFFFFFFFFFFFFFF : (1ULL << (size * 8)) - 1;
    *ctx.vsp = (a + b) & mask;
}

void Interpreter::op_sub(const uint8_t*& vip, VMContext& ctx, uint8_t size) {
    (void)vip;
    uint64_t b = *ctx.vsp++;
    uint64_t a = *ctx.vsp;
    uint64_t mask = (size == 8) ? 0xFFFFFFFFFFFFFFFF : (1ULL << (size * 8)) - 1;
    *ctx.vsp = (a - b) & mask;
}

void Interpreter::op_mul(const uint8_t*& vip, VMContext& ctx, uint8_t size) {
    (void)vip;
    uint64_t b = *ctx.vsp++;
    uint64_t a = *ctx.vsp;
    uint64_t mask = (size == 8) ? 0xFFFFFFFFFFFFFFFF : (1ULL << (size * 8)) - 1;
    *ctx.vsp = (a * b) & mask;
}

void Interpreter::op_and(const uint8_t*& vip, VMContext& ctx, uint8_t size) {
    (void)vip;
    uint64_t b = *ctx.vsp++;
    uint64_t a = *ctx.vsp;
    uint64_t mask = (size == 8) ? 0xFFFFFFFFFFFFFFFF : (1ULL << (size * 8)) - 1;
    *ctx.vsp = (a & b) & mask;
}

void Interpreter::op_or(const uint8_t*& vip, VMContext& ctx, uint8_t size) {
    (void)vip;
    uint64_t b = *ctx.vsp++;
    uint64_t a = *ctx.vsp;
    uint64_t mask = (size == 8) ? 0xFFFFFFFFFFFFFFFF : (1ULL << (size * 8)) - 1;
    *ctx.vsp = (a | b) & mask;
}

void Interpreter::op_xor(const uint8_t*& vip, VMContext& ctx, uint8_t size) {
    (void)vip;
    uint64_t b = *ctx.vsp++;
    uint64_t a = *ctx.vsp;
    uint64_t mask = (size == 8) ? 0xFFFFFFFFFFFFFFFF : (1ULL << (size * 8)) - 1;
    *ctx.vsp = (a ^ b) & mask;
}

void Interpreter::op_read(const uint8_t*& vip, VMContext& ctx, uint8_t size) {
    (void)vip;
    uint64_t addr = *ctx.vsp;
    uint64_t val = 0;
    std::memcpy(&val, reinterpret_cast<void*>(addr), size);
    *ctx.vsp = val;
}

void Interpreter::op_write(const uint8_t*& vip, VMContext& ctx, uint8_t size) {
    (void)vip;
    uint64_t val = *ctx.vsp++;
    uint64_t addr = *ctx.vsp++;
    std::memcpy(reinterpret_cast<void*>(addr), &val, size);
}

void Interpreter::op_jmp(const uint8_t*& vip, VMContext& ctx) {
    uint64_t rva = *ctx.vsp++;
    vip = reinterpret_cast<const uint8_t*>(ctx.module_base + rva);
    decrypt_->init_key(reinterpret_cast<uint64_t>(vip));
}

void Interpreter::op_ret(const uint8_t*& vip, VMContext& ctx) {
    (void)vip;
    (void)ctx;
}

void Interpreter::op_exit(const uint8_t*& vip, VMContext& ctx) {
    (void)vip;
    (void)ctx;
}

} // namespace nexus
