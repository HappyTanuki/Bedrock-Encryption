cmake_minimum_required (VERSION 3.25)
# ============================================================
# Policy
# ============================================================
include("${CMAKE_CURRENT_SOURCE_DIR}/.cmake/policy.cmake")

# ============================================================
# Project
# ============================================================
if(NOT DEFINED ROOT_PROJECT_NAME)
    set(ROOT_PROJECT_NAME "Root")
endif()

set(SUB_PROJECT_NAME "Encryption")
project(${SUB_PROJECT_NAME} LANGUAGES CXX)

set(CMAKE_CXX_STANDARD             23)
set(CMAKE_CXX_STANDARD_REQUIRED    ON)
set(CMAKE_CXX_EXTENSIONS          OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS  ON)

# ============================================================
# Sanity check: x86_64 (AMD64) 전용 빌드
# ============================================================
# 본 라이브러리는 x86 AES-NI / SSE2 / SSSE3 intrinsic을 직접 사용하므로
# 다른 ISA(ARM, i386 등)에서는 컴파일이 깨집니다. 잘못된 환경에서 빌드를
# 시도했을 때 친절한 에러로 먼저 차단합니다.
#
# 거부 대상:
#   - 32-bit (i386 / i686 / x86): Windows 32-bit cl, Linux -m32 multilib 없음 등
#   - ARM 64/32 (aarch64 / arm): x86 intrinsic 부재
#   - 그 외 ISA (ppc, riscv 등)
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR
        "Encryption: 64-bit build required (got ${CMAKE_SIZEOF_VOID_P}-byte pointers).\n"
        "  CMAKE_CXX_COMPILER = ${CMAKE_CXX_COMPILER}\n"
        "  Resolution (Windows): launch from \"x64 Native Tools Command Prompt for VS\" "
        "or select an x64 kit in VS Code CMake Tools.\n"
        "  Resolution (Linux): install x86_64 toolchain + multilib if needed; this preset uses -m64.")
endif()

string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" _enc_arch_lower)
if(NOT _enc_arch_lower MATCHES "^(amd64|x86_64|x64)$")
    message(FATAL_ERROR
        "Encryption: only x86_64 (AMD64) is supported.\n"
        "  CMAKE_SYSTEM_PROCESSOR = '${CMAKE_SYSTEM_PROCESSOR}'\n"
        "  Reason: this library uses x86 AES-NI / SSE2 / SSSE3 intrinsics that have no "
        "equivalent on other ISAs (ARM, RISC-V, PowerPC, etc.). Porting requires "
        "rewriting bedrock::cipher::AES_NI and replacing -maes / -msse2 / -mssse3 flags.")
endif()
unset(_enc_arch_lower)

# ============================================================
# Linkage option (cross-platform abstraction of MT/MD)
# ============================================================
# DYNAMIC: 결과물 SHARED + 시스템 런타임 동적 (Win=MD, Linux=.so + libstdc++.so)
# STATIC : 결과물 STATIC + 시스템 런타임 정적 (Win=MT, Linux=musl만 허용)
include("${CMAKE_CURRENT_SOURCE_DIR}/.cmake/linkage.cmake")

# ============================================================
# Dependencies – Common
# ============================================================
include(FetchContent)

if(NOT TARGET Common)
    FetchContent_Declare(
        Common
        GIT_REPOSITORY https://github.com/HappyTanuki/Bedrock-Common.git
        GIT_TAG        master
        GIT_SHALLOW    ON
    )
    FetchContent_MakeAvailable(Common)
endif()

include("${CMAKE_CURRENT_SOURCE_DIR}/.cmake/openssl.cmake")

# ============================================================
# Target – Encryption
# ============================================================
file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS "src/*.cc")

if(ENCRYPTION_LINKAGE STREQUAL "DYNAMIC")
    add_library(${SUB_PROJECT_NAME} SHARED ${SOURCES})
else()
    add_library(${SUB_PROJECT_NAME} STATIC ${SOURCES})
endif()

target_link_libraries(${SUB_PROJECT_NAME} PUBLIC ${ROOT_PROJECT_NAME}::Common)
if(ENCRYPTION_USE_OPENSSL)
    target_link_libraries(${SUB_PROJECT_NAME} PUBLIC OpenSSL::Crypto)
    target_link_libraries(${SUB_PROJECT_NAME} PUBLIC OpenSSL::SSL)

    # Only inject our self-built include dir; the system path is carried
    # by the IMPORTED target's INTERFACE_INCLUDE_DIRECTORIES.
    if(ENCRYPTION_OPENSSL_BUILD_FROM_SOURCE)
        target_include_directories(${SUB_PROJECT_NAME} SYSTEM PUBLIC "${OPENSSL_INCLUDE_DIR}")
    endif()
endif()
target_include_directories(${SUB_PROJECT_NAME} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

# Alias for parent projects
add_library(${ROOT_PROJECT_NAME}::${SUB_PROJECT_NAME} ALIAS ${SUB_PROJECT_NAME})

include("${CMAKE_CURRENT_SOURCE_DIR}/.cmake/compiler_options.cmake")

# ============================================================
# compile_commands.json copy (clangd/IDE intellisense용)
# ============================================================
# symlink는 Windows에서 관리자 권한이 필요하므로 copy_if_different로 처리.
#
# CMake 단계 순서(configure → generate) 때문에 단일 cmake 호출로는 자기 generate
# 결과를 만지지 못합니다. 이중 안전망으로 처리:
#   (1) configure 시점 execute_process: 이전 configure가 남긴 compile_commands.json이
#       있으면 즉시 copy. 첫 configure에는 source가 없어 silent fail (정상).
#       두 번째 configure부터 intellisense 즉시 활성화.
#   (2) add_custom_target(ALL): 빌드 시점 보장. 첫 빌드 후 항상 최신.
if (PROJECT_IS_TOP_LEVEL AND CMAKE_EXPORT_COMPILE_COMMANDS)
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${CMAKE_BINARY_DIR}/compile_commands.json
                ${CMAKE_BINARY_DIR}/../compile_commands.json
        OUTPUT_QUIET
        ERROR_QUIET
    )
    add_custom_target(copy_compile_commands ALL
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${CMAKE_BINARY_DIR}/compile_commands.json
                ${CMAKE_BINARY_DIR}/../compile_commands.json
        COMMENT "Copying compile_commands.json to project root"
        VERBATIM
    )
endif()

include("${CMAKE_CURRENT_SOURCE_DIR}/.cmake/post_build.cmake")

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/.cmake/cmake_include/config.h.in" "${CMAKE_CURRENT_BINARY_DIR}/config.h" @ONLY)
target_include_directories(${SUB_PROJECT_NAME} SYSTEM PUBLIC "${CMAKE_CURRENT_BINARY_DIR}")
