cmake_minimum_required(VERSION 3.10)
project(NexusRev)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Use the downloaded LIEF SDK
set(LIEF_SDK_PATH "/usr/local")
set(LIEF_INCLUDE_DIR "${LIEF_SDK_PATH}/include")
set(LIEF_LIBRARY "/usr/local/lib/libLIEF.so")

find_library(CAPSTONE_LIB capstone REQUIRED)

include_directories(include)
if(LIEF_INCLUDE_DIR)
    include_directories(${LIEF_INCLUDE_DIR})
endif()

add_executable(nexusrev 
    src/main.cpp 
    src/nexusrev.cpp
)

target_link_libraries(nexusrev 
    ${LIEF_LIBRARY} 
    ${CAPSTONE_LIB}
)
