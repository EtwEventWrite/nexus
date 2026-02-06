#pragma once

#include <capstone/capstone.h>
#include <cstdint>
#include <vector>
#include <string>

namespace nexus {

struct ARM64Instr {
    uint64_t address = 0;
    uint16_t size = 0;
    unsigned int id = 0;
    std::string mnemonic;
    std::string op_str;
    uint8_t bytes[16] = {};
    
    bool is_arithmetic() const;
    bool is_memory() const;
    bool is_branch() const;
    bool is_system() const;
};

class ARM64Disassembler {
public:
    ARM64Disassembler();
    ~ARM64Disassembler();
    
    bool disassemble(const uint8_t* code, size_t size, uint64_t base_addr,
                     std::vector<ARM64Instr>& out);
    
    static const char* reg_name(unsigned int reg_id);
    
private:
    csh handle_ = 0;
};

} // namespace nexus
