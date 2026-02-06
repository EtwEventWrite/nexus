add_executable(nexus_vm
    main.cpp
    vm/bytecode.cpp
    vm/decrypt.cpp
    vm/interpreter.cpp
    vm/transform.cpp
    lifter/arm64_lifter.cpp
)

target_include_directories(nexus_vm PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${capstone_SOURCE_DIR}/include
)

target_link_libraries(nexus_vm PRIVATE capstone-static)
