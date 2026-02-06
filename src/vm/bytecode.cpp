#include "vm/bytecode.hpp"
#include <cstring>

namespace nexus {

void BytecodeStream::emit_op(Opcode op) {
    bytes_.push_back(static_cast<uint8_t>(op));
}

void BytecodeStream::emit_op_imm(Opcode op, uint64_t imm, uint8_t imm_sz) {
    bytes_.push_back(static_cast<uint8_t>(op));
    const uint8_t* p = reinterpret_cast<const uint8_t*>(&imm);
    for (uint8_t i = 0; i < imm_sz && i < 8; ++i) {
        bytes_.push_back(p[i]);
    }
}

void BytecodeStream::emit_op_reg(Opcode op, uint8_t reg_idx) {
    bytes_.push_back(static_cast<uint8_t>(op));
    bytes_.push_back(reg_idx);
}

} // namespace nexus
