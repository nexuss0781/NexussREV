cmake_minimum_required(VERSION 3.24)
project(NexussREV VERSION 0.1.0 LANGUAGES CXX)

option(NEXUSREV_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(NEXUSREV_WARNINGS_AS_ERRORS "Treat project compiler warnings as errors" ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(LIEF 0.17.6 CONFIG REQUIRED)
find_package(capstone 5.0.9 CONFIG REQUIRED)
find_package(Python3 COMPONENTS Interpreter REQUIRED)

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
target_link_libraries(nexusrev PRIVATE LIEF::LIEF capstone::capstone)
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
    src/phase3.cpp
    src/phase4.cpp
    src/pe_image.cpp
    src/sha256.cpp
)
target_include_directories(nexusrev_unit_tests PRIVATE include)
target_link_libraries(nexusrev_unit_tests PRIVATE capstone::capstone)
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
set_tests_properties(nexusrev_cli_tests PROPERTIES TIMEOUT 60)

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
