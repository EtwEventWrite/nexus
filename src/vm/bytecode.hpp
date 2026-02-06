#pragma once

#include <cstdint>
#include <vector>

namespace nexus {

enum class Opcode : uint8_t {
    NOP = 0,
    PUSH_I8, PUSH_I16, PUSH_I32, PUSH_I64,
    POP, DUP, SWAP,
    
    LREG8, LREG16, LREG32, LREG64,
    SREG8, SREG16, SREG32, SREG64,
    
    ADD8, ADD16, ADD32, ADD64,
    SUB8, SUB16, SUB32, SUB64,
    MUL8, MUL16, MUL32, MUL64,
    DIV8, DIV16, DIV32, DIV64,
    MOD8, MOD16, MOD32, MOD64,
    
    ADD_S, SUB_S, MUL_S, DIV_S,
    
    AND8, AND16, AND32, AND64,
    OR8,  OR16,  OR32,  OR64,
    XOR8, XOR16, XOR32, XOR64,
    NOT8, NOT16, NOT32, NOT64,
    SHL8, SHL16, SHL32, SHL64,
    SHR8, SHR16, SHR32, SHR64,
    SAR8, SAR16, SAR32, SAR64,
    ROL8, ROL16, ROL32, ROL64,
    ROR8, ROR16, ROR32, ROR64,
    
    READ8, READ16, READ32, READ64,
    WRITE8, WRITE16, WRITE32, WRITE64,
    
    JMP, JZ, JNZ, JC, JNC, JO, JNO, JS, JNS,
    CALL, RET, EXIT,
    PUSH_VSP, LOAD_VSP, PUSH_FLAGS, LOAD_FLAGS,
    OPAQUE_NOP,
    CHECK_INTEGRITY,
    
    OPCODE_COUNT
};

enum class OpSize : uint8_t { S8 = 1, S16 = 2, S32 = 4, S64 = 8 };

constexpr int SCRATCH_COUNT = 32;
constexpr int FLAGS_SCRATCH_IDX = 31;
constexpr size_t MAX_IMM_SIZE = 8;

struct VMOp {
    uint8_t opcode;
    uint8_t imm_size;
    uint8_t _pad[2];
    uint64_t imm;
};

class BytecodeStream {
public:
    void emit_op(Opcode op);
    void emit_op_imm(Opcode op, uint64_t imm, uint8_t imm_sz);
    void emit_op_reg(Opcode op, uint8_t reg_idx);
    
    const uint8_t* data() const { return bytes_.data(); }
    size_t size() const { return bytes_.size(); }
    void clear() { bytes_.clear(); }
    uint8_t* mutable_data() { return bytes_.data(); }
    
private:
    std::vector<uint8_t> bytes_;
};

} // namespace nexus
