#include "lifter/disasm.hpp"
#include <cstring>

namespace nexus {

bool ARM64Instr::is_arithmetic() const {
    return (id >= ARM64_INS_ADD && id <= ARM64_INS_UXTH) ||
           (id >= ARM64_INS_ADC && id <= ARM64_INS_ORN) ||
           id == ARM64_INS_MUL || id == ARM64_INS_SDIV || id == ARM64_INS_UDIV;
}

bool ARM64Instr::is_memory() const {
    return (id >= ARM64_INS_LDR && id <= ARM64_INS_LDXP) ||
           (id >= ARM64_INS_STR && id <= ARM64_INS_STXP) ||
           id == ARM64_INS_LDP || id == ARM64_INS_STP;
}

bool ARM64Instr::is_branch() const {
    return (id >= ARM64_INS_B && id <= ARM64_INS_BL) ||
           (id >= ARM64_INS_CBZ && id <= ARM64_INS_CBNZ) ||
           (id >= ARM64_INS_TBZ && id <= ARM64_INS_TBNZ) ||
           id == ARM64_INS_RET || id == ARM64_INS_BR;
}

bool ARM64Instr::is_system() const {
    return id == ARM64_INS_SVC || id == ARM64_INS_HVC || id == ARM64_INS_BRK ||
           id == ARM64_INS_NOP || id == ARM64_INS_YIELD;
}

ARM64Disassembler::ARM64Disassembler() {
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle_) != CS_ERR_OK) {
        handle_ = 0;
    }
    if (handle_) {
        cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);
    }
}

ARM64Disassembler::~ARM64Disassembler() {
    if (handle_) {
        cs_close(&handle_);
    }
}

bool ARM64Disassembler::disassemble(const uint8_t* code, size_t size, uint64_t base_addr,
                                    std::vector<ARM64Instr>& out) {
    if (!handle_) return false;
    
    cs_insn* insn = nullptr;
    size_t count = cs_disasm(handle_, code, size, base_addr, 0, &insn);
    
    if (count == 0) return false;
    
    out.clear();
    out.reserve(count);
    
    for (size_t i = 0; i < count; ++i) {
        ARM64Instr ai;
        ai.address = insn[i].address;
        ai.size = insn[i].size;
        ai.id = insn[i].id;
        ai.mnemonic = insn[i].mnemonic;
        ai.op_str = insn[i].op_str;
        std::memcpy(ai.bytes, insn[i].bytes, std::min(sizeof(ai.bytes), (size_t)insn[i].size));
        out.push_back(ai);
    }
    
    cs_free(insn, count);
    return true;
}

const char* ARM64Disassembler::reg_name(unsigned int reg_id) {
    return handle_ ? cs_reg_name(handle_, reg_id) : "";
}

} // namespace nexus
