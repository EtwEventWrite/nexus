# Nexus VM

ARM64 code virtualizer with rolling decryption and polymorphic transform chains.

## Build

```bash
mkdir build && cd build
cmake ..
cmake --build .
./nexus_vm
```

Requires CMake 3.18+, C++20, and Capstone (fetched automatically).

## Layout

```
src/
├── main.cpp
├── vm/
│   ├── bytecode.hpp/cpp
│   ├── transform.hpp/cpp
│   ├── decrypt.hpp/cpp
│   ├── interpreter.hpp/cpp
│   └── anti_analysis.hpp
└── lifter/
    └── arm64_lifter.hpp/cpp
```

## Usage

```cpp
#include "vm/bytecode.hpp"
#include "vm/decrypt.hpp"
#include "vm/interpreter.hpp"

nexus::BytecodeStream bc;
bc.emit_op_imm(nexus::Opcode::PUSH_I64, 42, 8);
bc.emit_op_imm(nexus::Opcode::PUSH_I64, 10, 8);
bc.emit_op(nexus::Opcode::ADD64);
bc.emit_op(nexus::Opcode::EXIT);

nexus::RollingDecrypt decrypt(seed);
nexus::Interpreter vm;
vm.set_decryptor(&decrypt);
nexus::VMContext ctx = { /* ... */ };
const uint8_t* vip = bc.data();
vm.execute(vip, ctx);
```

## License

MIT
