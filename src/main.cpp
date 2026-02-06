#include "vm/bytecode.hpp"
#include "vm/decrypt.hpp"
#include "vm/interpreter.hpp"
#include "vm/transform.hpp"
#include "lifter/arm64_lifter.hpp"
#include <iostream>
#include <vector>
#include <cstring>

using namespace nexus;

int main() {
    std::cout << "Nexus VM - ARM64 Virtualizer\n";
    std::cout << "===========================\n\n";

    RollingDecrypt decrypt(0xDEADBEEF);
    decrypt.set_passthrough(true);
    std::cout << "Decryptor initialized\n";


    BytecodeStream bytecode;
    bytecode.emit_op_imm(Opcode::PUSH_I64, 42, 8);
    bytecode.emit_op_imm(Opcode::PUSH_I64, 10, 8);
    bytecode.emit_op(Opcode::ADD64);
    bytecode.emit_op(Opcode::EXIT);

    std::cout << "Bytecode: PUSH 42, PUSH 10, ADD, EXIT\n";
    std::cout << "Bytecode size: " << bytecode.size() << " bytes\n";


    std::vector<uint64_t> stack_storage(256, 0);
    VMContext ctx{};
    ctx.scratch.fill(0);
    ctx.stack_base = stack_storage.data();
    ctx.stack_size = stack_storage.size();
    ctx.vsp = ctx.stack_base + ctx.stack_size - 1;
    ctx.module_base = 0;

    Interpreter vm;
    vm.set_decryptor(&decrypt);
    const uint8_t* vip = bytecode.data();
    vm.execute(vip, ctx);

    std::cout << "\nResult: 42 + 10 = " << *ctx.vsp << "\n";

    std::cout << "\n--- ARM64 Lifter ---\n";
    uint8_t arm64_ret[] = { 0xC0, 0x03, 0x5F, 0xD6 };
    BytecodeStream lifted;
    ARM64Lifter lifter;
    if (lifter.lift(arm64_ret, sizeof(arm64_ret), 0x1000, lifted)) {
        std::cout << "Lifted ARM64 RET to " << lifted.size() << " bytecode bytes\n";
    }

    std::cout << "\n--- Encrypted Mode ---\n";
    decrypt.set_passthrough(false);
    BytecodeStream bc2;
    bc2.emit_op_imm(Opcode::PUSH_I64, 100, 8);
    bc2.emit_op_imm(Opcode::PUSH_I64, 23, 8);
    bc2.emit_op(Opcode::ADD64);
    bc2.emit_op(Opcode::EXIT);

    std::vector<uint8_t> enc_bc(bc2.size());
    std::memcpy(enc_bc.data(), bc2.data(), bc2.size());
    decrypt.init_key(reinterpret_cast<uint64_t>(enc_bc.data()));

    for (size_t j = 0; j < enc_bc.size(); ) {
        uint8_t op = enc_bc[j];
        enc_bc[j] = decrypt.encrypt_opcode(op, enc_bc.data() + j);
        j++;
        if (op == static_cast<uint8_t>(Opcode::PUSH_I64)) {
            uint64_t imm;
            std::memcpy(&imm, enc_bc.data() + j, 8);
            uint64_t k = decrypt.get_rolling_key();
            imm = decrypt.encrypt_imm(imm, 8, k);
            decrypt.set_rolling_key(k);
            std::memcpy(enc_bc.data() + j, &imm, 8);
            j += 8;
        }
    }

    ctx.vsp = ctx.stack_base + ctx.stack_size - 1;
    ctx.scratch.fill(0);
    vip = enc_bc.data();
    vm.execute(vip, ctx);
    std::cout << "Encrypted run: 100 + 23 = " << *ctx.vsp << "\n";

    return 0;
}
