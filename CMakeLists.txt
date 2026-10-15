cmake_minimum_required(VERSION 3.24)
project(NexussREV VERSION 0.1.0 LANGUAGES CXX)

option(NEXUSREV_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(NEXUSREV_WARNINGS_AS_ERRORS "Treat project compiler warnings as errors" ON)
option(NEXUSREV_BUILD_FUZZERS "Build the optional libFuzzer Phase 6 harness" OFF)
option(NEXUSREV_ENABLE_ZYDIS_CROSSCHECK "Build the optional test-only Zydis decoder cross-check" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(LIEF 0.17.6 CONFIG REQUIRED)
find_package(capstone 5.0.9 CONFIG REQUIRED)
find_package(Python3 COMPONENTS Interpreter REQUIRED)
find_package(Threads REQUIRED)

add_executable(nexusrev
    src/main.cpp
    src/phase1.cpp
    src/phase2.cpp
    src/phase3.cpp
    src/phase4.cpp
    src/pe_image.cpp
    src/sha256.cpp
)
target_include_directories(nexusrev PRIVATE include)
target_link_libraries(nexusrev PRIVATE LIEF::LIEF capstone::capstone Threads::Threads)
target_compile_definitions(nexusrev PRIVATE
    NEXUSREV_VERSION="${PROJECT_VERSION}"
    NEXUSREV_LIEF_VERSION="0.17.6"
    NEXUSREV_CAPSTONE_VERSION="5.0.9"
)

function(nexusrev_apply_build_options target_name)
    if(MSVC)
        target_compile_options(${target_name} PRIVATE /W4 /permissive-)
        if(NEXUSREV_WARNINGS_AS_ERRORS)
            target_compile_options(${target_name} PRIVATE /WX)
        endif()
    else()
        target_compile_options(${target_name} PRIVATE -Wall -Wextra -Wpedantic)
        if(NEXUSREV_WARNINGS_AS_ERRORS)
            target_compile_options(${target_name} PRIVATE -Werror)
        endif()
        if(NEXUSREV_ENABLE_SANITIZERS AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
            target_compile_options(${target_name} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
            target_link_options(${target_name} PRIVATE -fsanitize=address,undefined)
        endif()
    endif()
endfunction()

nexusrev_apply_build_options(nexusrev)

enable_testing()
add_executable(nexusrev_unit_tests
    tests/unit_tests.cpp
    src/phase1.cpp
    src/phase2.cpp
    src/phase3.cpp
    src/phase4.cpp
    src/pe_image.cpp
    src/sha256.cpp
)
target_include_directories(nexusrev_unit_tests PRIVATE include)
target_link_libraries(nexusrev_unit_tests PRIVATE LIEF::LIEF capstone::capstone Threads::Threads)
nexusrev_apply_build_options(nexusrev_unit_tests)
add_test(NAME nexusrev_unit_tests COMMAND nexusrev_unit_tests)

add_test(
    NAME nexusrev_cli_tests
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_tests.py
            --program $<TARGET_FILE:nexusrev>
            --fixture ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/minimal-pe-x64.exe
            --generator ${CMAKE_CURRENT_SOURCE_DIR}/tests/make_phase1_fixture.py
            --compiler-fixture ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/compiler-generated-x64.exe
            --phase2-fixtures ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/phase2
            --schema ${CMAKE_CURRENT_SOURCE_DIR}/docs/analysis-report.schema.json
)
set_tests_properties(nexusrev_cli_tests PROPERTIES TIMEOUT 120)

add_test(
    NAME nexusrev_phase6_hardening
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/phase6_hardening.py
            --program $<TARGET_FILE:nexusrev>
            --fixture ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/minimal-pe-x64.exe
            --generator ${CMAKE_CURRENT_SOURCE_DIR}/tests/make_phase1_fixture.py
            --schema-v5 ${CMAKE_CURRENT_SOURCE_DIR}/docs/analysis-report-v5.schema.json
            --schema-v6 ${CMAKE_CURRENT_SOURCE_DIR}/docs/analysis-report.schema.json
)
set_tests_properties(nexusrev_phase6_hardening PROPERTIES TIMEOUT 180)

add_test(
    NAME nexusrev_phase2_benchmark
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/phase2_benchmark.py
            --program $<TARGET_FILE:nexusrev>
            --manifest ${CMAKE_CURRENT_SOURCE_DIR}/tests/benchmarks/v1/corpus.json
            --baseline ${CMAKE_CURRENT_SOURCE_DIR}/tests/benchmarks/v1/baseline.json
            --output ${CMAKE_CURRENT_BINARY_DIR}/phase2-benchmark-results.json
)
set_tests_properties(nexusrev_phase2_benchmark PROPERTIES TIMEOUT 120)

add_test(
    NAME nexusrev_phase4_benchmark
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/phase4_benchmark.py
            --program $<TARGET_FILE:nexusrev>
            --ground-truth ${CMAKE_CURRENT_SOURCE_DIR}/tests/benchmarks/v1/phase4-ground-truth.json
            --fixtures ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures
            --output ${CMAKE_CURRENT_BINARY_DIR}/phase4-benchmark-results.json
)
set_tests_properties(nexusrev_phase4_benchmark PROPERTIES TIMEOUT 120)

add_test(
    NAME nexusrev_phase5_validation
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/phase5_validation.py
            --program $<TARGET_FILE:nexusrev>
            --corpus ${CMAKE_CURRENT_SOURCE_DIR}/tests/benchmarks/v1/phase5-corpus.json
            --phase2-manifest ${CMAKE_CURRENT_SOURCE_DIR}/tests/benchmarks/v1/corpus.json
            --phase2-baseline ${CMAKE_CURRENT_SOURCE_DIR}/tests/benchmarks/v1/baseline.json
            --phase4-ground-truth ${CMAKE_CURRENT_SOURCE_DIR}/tests/benchmarks/v1/phase4-ground-truth.json
            --phase4-results ${CMAKE_CURRENT_BINARY_DIR}/phase4-benchmark-results.json
            --release-baseline ${CMAKE_CURRENT_SOURCE_DIR}/tests/benchmarks/v1/phase5-baseline.json
            --schema ${CMAKE_CURRENT_SOURCE_DIR}/docs/analysis-report.schema.json
            --output ${CMAKE_CURRENT_BINARY_DIR}/phase5-validation-results.json
)
set_tests_properties(nexusrev_phase5_validation PROPERTIES
    DEPENDS nexusrev_phase4_benchmark
    TIMEOUT 240
)

if(NEXUSREV_ENABLE_ZYDIS_CROSSCHECK)
    find_package(zydis 4.1.1 CONFIG REQUIRED)
    add_executable(nexusrev_decoder_crosscheck
        tests/decoder_crosscheck.cpp
        src/pe_image.cpp
        src/sha256.cpp
    )
    target_include_directories(nexusrev_decoder_crosscheck PRIVATE include)
    target_link_libraries(nexusrev_decoder_crosscheck PRIVATE
        LIEF::LIEF capstone::capstone Zydis::Zydis Threads::Threads
    )
    nexusrev_apply_build_options(nexusrev_decoder_crosscheck)
    add_test(
        NAME nexusrev_decoder_crosscheck
        COMMAND $<TARGET_FILE:nexusrev_decoder_crosscheck>
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/compiler-generated-x64.exe
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/compiler-generated-x64-ghidra-11.3.2.tsv
    )
    set_tests_properties(nexusrev_decoder_crosscheck PROPERTIES TIMEOUT 120)
endif()

include(GNUInstallDirs)
if(UNIX AND NOT APPLE)
    set_target_properties(nexusrev PROPERTIES INSTALL_RPATH "$ORIGIN/../${CMAKE_INSTALL_LIBDIR}")
endif()
install(TARGETS nexusrev
    RUNTIME_DEPENDENCIES
    PRE_EXCLUDE_REGEXES "api-ms-.*" "ext-ms-.*"
    POST_EXCLUDE_REGEXES "^/System/Library/" "^/usr/lib/" "^/lib/"
        "[/\\\\]Windows[/\\\\]System32[/\\\\]"
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(FILES
    README.md LICENSE
    docs/analysis-report.schema.json
    docs/analysis-report-v5.schema.json
    docs/phase6-release-notes.md
    docs/dependency-license-inventory.md
    DESTINATION ${CMAKE_INSTALL_DATADIR}/nexusrev
)
if(DEFINED VCPKG_INSTALLED_DIR AND DEFINED VCPKG_TARGET_TRIPLET)
    set(_nexusrev_vcpkg_share "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/share")
    file(GLOB _nexusrev_vcpkg_copyrights CONFIGURE_DEPENDS
        "${_nexusrev_vcpkg_share}/*/copyright")
    if(NOT _nexusrev_vcpkg_copyrights)
        message(FATAL_ERROR "No installed vcpkg copyright notices found under ${_nexusrev_vcpkg_share}")
    endif()
    foreach(_copyright_file IN LISTS _nexusrev_vcpkg_copyrights)
        get_filename_component(_port_share_dir "${_copyright_file}" DIRECTORY)
        get_filename_component(_port_name "${_port_share_dir}" NAME)
        install(FILES "${_copyright_file}"
            DESTINATION "${CMAKE_INSTALL_DATADIR}/nexusrev/licenses/${_port_name}")
    endforeach()
else()
    install(CODE "message(FATAL_ERROR \"Release packaging requires the vcpkg installed tree so third-party copyright notices can be bundled.\")")
endif()

set(CPACK_PACKAGE_NAME "NexussREV")
set(CPACK_PACKAGE_VENDOR "NexussREV contributors")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Static PE32+ x86-64 analysis and evidence reporting")
set(CPACK_PACKAGE_FILE_NAME "NexussREV-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_GENERATOR "TGZ;ZIP")
include(CPack)

if(NEXUSREV_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "NEXUSREV_BUILD_FUZZERS requires Clang/libFuzzer")
    endif()
    add_executable(nexusrev_phase6_fuzz
        tests/fuzz/phase6_fuzz.cpp
        src/phase1.cpp
        src/phase2.cpp
        src/phase3.cpp
        src/phase4.cpp
        src/pe_image.cpp
        src/sha256.cpp
    )
    target_include_directories(nexusrev_phase6_fuzz PRIVATE include)
    target_link_libraries(nexusrev_phase6_fuzz PRIVATE LIEF::LIEF capstone::capstone)
    target_compile_definitions(nexusrev_phase6_fuzz PRIVATE
        NEXUSREV_VERSION="${PROJECT_VERSION}"
        NEXUSREV_LIEF_VERSION="0.17.6"
        NEXUSREV_CAPSTONE_VERSION="5.0.9"
    )
    target_compile_options(nexusrev_phase6_fuzz PRIVATE
        -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer
        -Wall -Wextra -Wpedantic
    )
    target_link_options(nexusrev_phase6_fuzz PRIVATE -fsanitize=fuzzer,address,undefined)
endif()
