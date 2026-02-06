#include "lifter/arm64_lifter.hpp"
#include <capstone/capstone.h>
#include <cstring>

namespace nexus {

static int reg_to_scratch(unsigned int reg_id) {
    if (reg_id >= ARM64_REG_X0 && reg_id <= ARM64_REG_X30)
        return reg_id - ARM64_REG_X0;
    if (reg_id >= ARM64_REG_W0 && reg_id <= ARM64_REG_W30)
        return reg_id - ARM64_REG_W0;
    if (reg_id == ARM64_REG_SP) return 31;
    return -1;
}

ARM64Lifter::ARM64Lifter() {
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle_) != CS_ERR_OK)
        handle_ = 0;
    if (handle_)
        cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);
}

ARM64Lifter::~ARM64Lifter() {
    if (handle_) cs_close(&handle_);
}

bool ARM64Lifter::lift(const uint8_t* code, size_t size, uint64_t base_addr,
                       BytecodeStream& out) {
    if (!handle_) return false;

    cs_insn* insn = nullptr;
    size_t count = cs_disasm(handle_, code, size, base_addr, 0, &insn);
    if (count == 0) return false;

    for (size_t i = 0; i < count; ++i) {
        if (!lift_insn(&insn[i], out))
            break;
    }
    cs_free(insn, count);
    return true;
}

bool ARM64Lifter::lift_insn(cs_insn* insn, BytecodeStream& out) {
    if (!insn->detail || insn->detail->arm64.op_count == 0) {
        switch (insn->id) {
            case ARM64_INS_RET:
                out.emit_op(Opcode::RET);
                return true;
            case ARM64_INS_NOP:
                out.emit_op(Opcode::NOP);
                return true;
            default:
                out.emit_op(Opcode::EXIT);
                return true;
        }
    }

    const cs_arm64& arm64 = insn->detail->arm64;
    const cs_arm64_op* ops = arm64.operands;

    switch (insn->id) {
        case ARM64_INS_ADD:
        case ARM64_INS_ADDS: {
            if (arm64.op_count < 3) break;
            int dst = reg_to_scratch(ops[0].reg);
            int src1 = reg_to_scratch(ops[1].reg);
            if (dst < 0 || src1 < 0) break;
            if (ops[2].type == ARM64_OP_REG) {
                int src2 = reg_to_scratch(ops[2].reg);
                if (src2 < 0) break;
                out.emit_op_reg(Opcode::LREG64, src1);
                out.emit_op_reg(Opcode::LREG64, src2);
                out.emit_op(Opcode::ADD64);
                out.emit_op_reg(Opcode::SREG64, dst);
            } else if (ops[2].type == ARM64_OP_IMM) {
                out.emit_op_imm(Opcode::PUSH_I64, ops[2].imm, 8);
                out.emit_op_reg(Opcode::LREG64, src1);
                out.emit_op(Opcode::ADD64);
                out.emit_op_reg(Opcode::SREG64, dst);
            }
            return true;
        }
        case ARM64_INS_SUB:
        case ARM64_INS_SUBS: {
            if (arm64.op_count < 3) break;
            int dst = reg_to_scratch(ops[0].reg);
            int src1 = reg_to_scratch(ops[1].reg);
            if (dst < 0 || src1 < 0) break;
            if (ops[2].type == ARM64_OP_REG) {
                int src2 = reg_to_scratch(ops[2].reg);
                if (src2 < 0) break;
                out.emit_op_reg(Opcode::LREG64, src1);
                out.emit_op_reg(Opcode::LREG64, src2);
                out.emit_op(Opcode::SUB64);
                out.emit_op_reg(Opcode::SREG64, dst);
            } else if (ops[2].type == ARM64_OP_IMM) {
                out.emit_op_reg(Opcode::LREG64, src1);
                out.emit_op_imm(Opcode::PUSH_I64, ops[2].imm, 8);
                out.emit_op(Opcode::SUB64);
                out.emit_op_reg(Opcode::SREG64, dst);
            }
            return true;
        }
        case ARM64_INS_MOV:
        case ARM64_INS_MOVZ:
        case ARM64_INS_MOVK: {
            if (arm64.op_count < 2) break;
            int dst = reg_to_scratch(ops[0].reg);
            if (dst < 0) break;
            if (ops[1].type == ARM64_OP_REG) {
                int src = reg_to_scratch(ops[1].reg);
                if (src < 0) break;
                out.emit_op_reg(Opcode::LREG64, src);
                out.emit_op_reg(Opcode::SREG64, dst);
            } else if (ops[1].type == ARM64_OP_IMM) {
                out.emit_op_imm(Opcode::PUSH_I64, ops[1].imm, 8);
                out.emit_op_reg(Opcode::SREG64, dst);
            }
            return true;
        }
        case ARM64_INS_LDR: {
            if (arm64.op_count < 2) break;
            int dst = reg_to_scratch(ops[0].reg);
            if (dst < 0) break;
            if (ops[1].type == ARM64_OP_MEM) {
                int base = reg_to_scratch(ops[1].mem.base);
                if (base < 0) break;
                out.emit_op_reg(Opcode::LREG64, base);
                if (ops[1].mem.disp != 0) {
                    out.emit_op_imm(Opcode::PUSH_I64, ops[1].mem.disp, 8);
                    out.emit_op(Opcode::ADD64);
                }
                out.emit_op(Opcode::READ64);
                out.emit_op_reg(Opcode::SREG64, dst);
            }
            return true;
        }
        case ARM64_INS_STR: {
            if (arm64.op_count < 2) break;
            if (ops[1].type == ARM64_OP_MEM) {
                int base = reg_to_scratch(ops[1].mem.base);
                int src = reg_to_scratch(ops[0].reg);
                if (base < 0 || src < 0) break;
                out.emit_op_reg(Opcode::LREG64, base);
                if (ops[1].mem.disp != 0) {
                    out.emit_op_imm(Opcode::PUSH_I64, ops[1].mem.disp, 8);
                    out.emit_op(Opcode::ADD64);
                }
                out.emit_op_reg(Opcode::LREG64, src);
                out.emit_op(Opcode::WRITE64);
            }
            return true;
        }
        case ARM64_INS_RET:
            out.emit_op(Opcode::RET);
            return true;
        case ARM64_INS_NOP:
            out.emit_op(Opcode::NOP);
            return true;
        case ARM64_INS_BR:
        case ARM64_INS_BLR:
            out.emit_op(Opcode::EXIT);
            return true;
        default:
            out.emit_op(Opcode::EXIT);
            return true;
    }
    out.emit_op(Opcode::EXIT);
    return true;
}

} // namespace nexus
