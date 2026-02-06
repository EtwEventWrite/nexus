#pragma once

#include "vm/bytecode.hpp"
#include <capstone/capstone.h>
#include <vector>
#include <cstdint>

namespace nexus {

class ARM64Lifter {
public:
    ARM64Lifter();
    ~ARM64Lifter();

    bool lift(const uint8_t* code, size_t size, uint64_t base_addr,
              BytecodeStream& out);

private:
    csh handle_ = 0;

    bool lift_insn(cs_insn* insn, BytecodeStream& out);
};

} // namespace nexus
