cmake_minimum_required (VERSION 3.25)

# ============================================================
# Policy
# ============================================================
# CMP0091: "Honor standard library usage requirements when using MSVC toolset"
if(WIN32 AND POLICY CMP0091)
    cmake_policy(SET CMP0091 NEW)
endif()
# CMP0141: "Allow MSVC to use Edit and Continue when using the Program Database format for debug information"
if (WIN32 AND POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

# ============================================================
# Project
# ============================================================
set(SUB_PROJECT_NAME "Encryption")
project(${SUB_PROJECT_NAME} LANGUAGES CXX)

set(CMAKE_CXX_STANDARD             23)
set(CMAKE_CXX_STANDARD_REQUIRED    ON)
set(CMAKE_CXX_EXTENSIONS          OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS  ON)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(HOST_ARCH_AMD64 TRUE)
else()
  set(HOST_ARCH_AMD64 FALSE)
endif()

# ============================================================
# Linkage option (cross-platform abstraction of MT/MD)
# ============================================================
# DYNAMIC: 결과물 SHARED + 시스템 런타임 동적 (Win=MD, Linux=.so + libstdc++.so)
# STATIC : 결과물 STATIC + 시스템 런타임 정적 (Win=MT, Linux=musl만 허용)
set(ENCRYPTION_LINKAGE "DYNAMIC" CACHE STRING
    "Library and runtime linkage: DYNAMIC or STATIC")
set_property(CACHE ENCRYPTION_LINKAGE PROPERTY STRINGS DYNAMIC STATIC)

# ============================================================
# Detect libc on Linux (glibc / musl / other)
# ============================================================
set(ENCRYPTION_LIBC "unknown")
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    include(CheckSymbolExists)
    check_symbol_exists(__GLIBC__ "features.h" ENCRYPTION_HAVE_GLIBC)

    if(ENCRYPTION_HAVE_GLIBC)
        set(ENCRYPTION_LIBC "glibc")
    else()
        execute_process(
            COMMAND ${CMAKE_C_COMPILER} -dumpmachine
            OUTPUT_VARIABLE _cc_triple
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
        )
        if(_cc_triple MATCHES "musl")
            set(ENCRYPTION_LIBC "musl")
        else()
            file(GLOB _musl_loader "/lib/ld-musl-*.so*" "/lib64/ld-musl-*.so*")
            if(_musl_loader)
                set(ENCRYPTION_LIBC "musl")
            else()
                set(ENCRYPTION_LIBC "other")
            endif()
        endif()
    endif()
    message(STATUS "Encryption: detected libc = ${ENCRYPTION_LIBC}")
endif()

# ============================================================
# License guard: glibc + STATIC linkage is disallowed
# ============================================================
# glibc는 LGPL-2.1 라이선스라 정적 링크 시 재링크 가능 형태 배포 등
# 별도 의무가 발생합니다. 이 프로젝트는 해당 의무를 회피하기 위해
# glibc 환경에서의 STATIC 빌드를 차단합니다.
# 정적 빌드를 원하면 musl 기반 환경(예: Alpine Linux)에서 빌드하세요.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux"
   AND ENCRYPTION_LINKAGE STREQUAL "STATIC"
   AND ENCRYPTION_LIBC STREQUAL "glibc")
    message(FATAL_ERROR
        "Encryption: STATIC linkage is not allowed on glibc.\n"
        "  Reason: glibc is licensed under LGPL-2.1, and static linking "
        "imposes redistribution obligations (relinkable object files, "
        "license notice, etc.) that this project chooses not to undertake.\n"
        "  Resolution: build on a musl-based environment (e.g. Alpine Linux), "
        "or use ENCRYPTION_LINKAGE=DYNAMIC.")
endif()

# ============================================================
# Apply MSVC runtime based on ENCRYPTION_LINKAGE
# (preset이 직접 지정한 경우엔 건드리지 않음)
# ============================================================
if(WIN32 AND NOT CMAKE_MSVC_RUNTIME_LIBRARY)
    if(ENCRYPTION_LINKAGE STREQUAL "STATIC")
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    else()
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
    endif()
endif()

# ============================================================
# Dependencies – Common
# ============================================================
include(FetchContent)
include(ExternalProject)
include(ProcessorCount)

if(NOT DEFINED ROOT_PROJECT_NAME)
    set(ROOT_PROJECT_NAME "Root")
endif()

if(NOT TARGET Common)
FetchContent_Declare(
    Common
    GIT_REPOSITORY https://github.com/HappyTanuki/Bedrock-Common.git
    GIT_TAG        master
    GIT_SHALLOW    ON
)
FetchContent_MakeAvailable(Common)
endif()

# ============================================================
# Dependencies – OpenSSL
# ============================================================
option(ENCRYPTION_USE_OPENSSL "Use OpenSSL (find on system, otherwise build from source)" ON)

# Source selection:
#   AUTO   - Try system first, fall back to building from source (default)
#   SYSTEM - Require system OpenSSL; fail configuration if not found
#   BUILD  - Always build from source (legacy behavior)
set(ENCRYPTION_OPENSSL_SOURCE "AUTO" CACHE STRING
    "Where to obtain OpenSSL: AUTO (system, then build), SYSTEM (system only), BUILD (always build)")
set_property(CACHE ENCRYPTION_OPENSSL_SOURCE PROPERTY STRINGS AUTO SYSTEM BUILD)

# Tracks whether OpenSSL must be built from source. Resolved below.
set(ENCRYPTION_OPENSSL_BUILD_FROM_SOURCE FALSE)

if(ENCRYPTION_USE_OPENSSL)
    # ---- 1) System OpenSSL discovery (skipped when SOURCE=BUILD) ----
    if(NOT ENCRYPTION_OPENSSL_SOURCE STREQUAL "BUILD")
        # find_package respects OPENSSL_ROOT_DIR / CMAKE_PREFIX_PATH, so
        # vcpkg / Conan / Homebrew / Firedaemon installs are picked up here.
        if(ENCRYPTION_LINKAGE STREQUAL "STATIC")
            set(OPENSSL_USE_STATIC_LIBS TRUE)
        endif()
        find_package(OpenSSL QUIET)

        if(OpenSSL_FOUND)
            message(STATUS "Encryption: using system OpenSSL ${OPENSSL_VERSION} (${OPENSSL_INCLUDE_DIR})")
        elseif(ENCRYPTION_OPENSSL_SOURCE STREQUAL "SYSTEM")
            message(FATAL_ERROR
                "Encryption: ENCRYPTION_OPENSSL_SOURCE=SYSTEM but OpenSSL was not found. "
                "Hint: install it via your package manager, or set OPENSSL_ROOT_DIR / CMAKE_PREFIX_PATH.")
        else()
            message(STATUS "Encryption: system OpenSSL not found, will build from source")
            set(ENCRYPTION_OPENSSL_BUILD_FROM_SOURCE TRUE)
        endif()
    else()
        message(STATUS "Encryption: ENCRYPTION_OPENSSL_SOURCE=BUILD, building OpenSSL from source")
        set(ENCRYPTION_OPENSSL_BUILD_FROM_SOURCE TRUE)
    endif()
endif()

# ============================================================
# Dependencies – OpenSSL (build from source)
# ============================================================
if(ENCRYPTION_OPENSSL_BUILD_FROM_SOURCE)
    # ============================================================
    # CPU Count
    # ============================================================
    ProcessorCount(NCPU)
    if(NCPU EQUAL 0)
        set(NCPU 1)
    endif()

    # ============================================================
    # OpenSSL – Paths
    # ============================================================
    set(OPENSSL_CONFIG_DIR_NAME "OpenSSL-Config")
    set(OPENSSL_DIR             "${CMAKE_CURRENT_BINARY_DIR}/OpenSSL-prefix/src")
    set(OPENSSL_SOURCE_DIR      "${OPENSSL_DIR}/OpenSSL")
    set(OPENSSL_INSTALL_DIR     "${OPENSSL_DIR}/OpenSSL-Install")
    set(OPENSSL_CONFIG_DIR      "${OPENSSL_DIR}/${OPENSSL_CONFIG_DIR_NAME}")
    set(OPENSSL_INCLUDE_DIR     "${OPENSSL_INSTALL_DIR}/include")
    set(OPENSSL_LIB_DIR         "${OPENSSL_INSTALL_DIR}/lib")
    set(OPENSSL_BIN_DIR         "${OPENSSL_INSTALL_DIR}/bin")
    set(OPENSSL_VERSION         "openssl-3.6.1")

    # ============================================================
    # OpenSSL – Runtime Libraries (per platform)
    # ============================================================
    if(NOT WIN32)
        set(OPENSSL_RUNTIME_LIBS
            "${OPENSSL_LIB_DIR}/libcrypto.so"
            "${OPENSSL_LIB_DIR}/libssl.so"
        )
    elseif(HOST_ARCH_AMD64)
        set(OPENSSL_RUNTIME_LIBS
            "${OPENSSL_BIN_DIR}/libcrypto-3-x64.dll"
            "${OPENSSL_BIN_DIR}/libssl-3-x64.dll"
        )
        set(OPENSSL_RUNTIME_CRYPTO_LIBS "${OPENSSL_BIN_DIR}/libcrypto-3-x64.dll")
        set(OPENSSL_RUNTIME_SSL_LIBS    "${OPENSSL_BIN_DIR}/libssl-3-x64.dll")
    else()
        set(OPENSSL_RUNTIME_LIBS
            "${OPENSSL_BIN_DIR}/libcrypto-3.dll"
            "${OPENSSL_BIN_DIR}/libssl-3.dll"
        )
        set(OPENSSL_RUNTIME_CRYPTO_LIBS "${OPENSSL_BIN_DIR}/libcrypto-3.dll")
        set(OPENSSL_RUNTIME_SSL_LIBS    "${OPENSSL_BIN_DIR}/libssl-3.dll")
    endif()

    # Create placeholder files so IMPORTED targets can resolve paths at configure time
    foreach(f ${OPENSSL_RUNTIME_LIBS})
        if(NOT EXISTS ${f})
            file(WRITE "${f}" "")
        endif()
    endforeach()

    # ============================================================
    # OpenSSL – Build Commands (per platform)
    # ============================================================
    set(OPENSSL_DEPENDENCY        "")
    set(OPENSSL_CONFIGURE_COMMAND "")
    set(OPENSSL_BUILD_COMMAND     "")
    set(OPENSSL_TEST_COMMAND      "")
    set(OPENSSL_INSTALL_COMMAND   "")

    if(NOT WIN32)
        # ---- Linux / macOS ----
        set(OPENSSL_CONFIGURE_COMMAND "${OPENSSL_SOURCE_DIR}/config")
        set(OPENSSL_BUILD_COMMAND     make -j${NCPU})
        set(OPENSSL_TEST_COMMAND      make -j${NCPU} test)
        set(OPENSSL_INSTALL_COMMAND   make -j${NCPU} install)
        set(OPENSSL_CRYPTO_LIB        "${OPENSSL_LIB_DIR}/libcrypto.so")
        set(OPENSSL_SSL_LIB           "${OPENSSL_LIB_DIR}/libssl.so")
    elseif(HOST_ARCH_AMD64 AND WIN32)
        # ---- Windows 64-bit ----
        ExternalProject_Add(
            Perl
            URL                        https://github.com/StrawberryPerl/Perl-Dist-Strawberry/releases/download/SP_54201_64bit/strawberry-perl-5.42.0.1-64bit-portable.zip
            
            USES_TERMINAL_DOWNLOAD  ${PROJECT_IS_TOP_LEVEL}
            USES_TERMINAL_UPDATE    ${PROJECT_IS_TOP_LEVEL}
            USES_TERMINAL_PATCH     ${PROJECT_IS_TOP_LEVEL}
            USES_TERMINAL_CONFIGURE ${PROJECT_IS_TOP_LEVEL}
            USES_TERMINAL_BUILD     ${PROJECT_IS_TOP_LEVEL}
            USES_TERMINAL_TEST      ${PROJECT_IS_TOP_LEVEL}
            USES_TERMINAL_INSTALL   ${PROJECT_IS_TOP_LEVEL}

            DOWNLOAD_EXTRACT_TIMESTAMP TRUE
            CONFIGURE_COMMAND          ""
            BUILD_COMMAND              ""
            INSTALL_COMMAND            ""
        )
        ExternalProject_Get_Property(Perl SOURCE_DIR)
        set(PERL_BIN_DIR "${SOURCE_DIR}/perl/bin")

        ExternalProject_Add(
            Nasm
            URL                        https://www.nasm.us/pub/nasm/releasebuilds/3.01/win64/nasm-3.01-win64.zip
            
            USES_TERMINAL_DOWNLOAD  ${PROJECT_IS_TOP_LEVEL}
            USES_TERMINAL_UPDATE    ${PROJECT_IS_TOP_LEVEL}
            USES_TERMINAL_PATCH     ${PROJECT_IS_TOP_LEVEL}
            USES_TERMINAL_CONFIGURE ${PROJECT_IS_TOP_LEVEL}
            USES_TERMINAL_BUILD     ${PROJECT_IS_TOP_LEVEL}
            USES_TERMINAL_TEST      ${PROJECT_IS_TOP_LEVEL}
            USES_TERMINAL_INSTALL   ${PROJECT_IS_TOP_LEVEL}

            DOWNLOAD_EXTRACT_TIMESTAMP TRUE
            CONFIGURE_COMMAND          ""
            BUILD_COMMAND              ""
            INSTALL_COMMAND            ""
        )
        ExternalProject_Get_Property(Nasm SOURCE_DIR)
        set(NASM_BIN_DIR "${SOURCE_DIR}")

        function(OPENSSL_DEPENDENCY_INJECT out_var)
            set(cmd ${ARGN})
            set(${out_var}
                ${CMAKE_COMMAND} -E env
                    --modify PATH=path_list_append:${PERL_BIN_DIR}
                    --modify PATH=path_list_append:${NASM_BIN_DIR}
                    CL=/MP
                    VSCMD_DEBUG=0
                --
                cmd /Q /C "call VsDevCmd.bat -host_arch=amd64 -arch=amd64 && ${cmd}"
                PARENT_SCOPE
            )
        endfunction()

        OPENSSL_DEPENDENCY_INJECT(OPENSSL_CONFIGURE_COMMAND "perl ${OPENSSL_SOURCE_DIR}/Configure VC-WIN64A")
        OPENSSL_DEPENDENCY_INJECT(OPENSSL_BUILD_COMMAND     "nmake")
        OPENSSL_DEPENDENCY_INJECT(OPENSSL_TEST_COMMAND      "nmake test")
        OPENSSL_DEPENDENCY_INJECT(OPENSSL_INSTALL_COMMAND   "nmake install")
        set(OPENSSL_DEPENDENCY                              Perl Nasm)
        set(OPENSSL_CRYPTO_LIB                              "${OPENSSL_LIB_DIR}/libcrypto.lib")
        set(OPENSSL_SSL_LIB                                 "${OPENSSL_LIB_DIR}/libssl.lib")
    else()
        # ---- Windows 32-bit ----
        ExternalProject_Add(
            Perl
            URL                        https://strawberryperl.com/download/5.32.1.1/strawberry-perl-no64-5.32.1.1-32bit-portable.zip
            
            USES_TERMINAL_DOWNLOAD  ${PROJECT_IS_TOP_LEVEL}
            USES_TERMINAL_UPDATE    ${PROJECT_IS_TOP_LEVEL}
            USES_TERMINAL_PATCH     ${PROJECT_IS_TOP_LEVEL}
            USES_TERMINAL_CONFIGURE ${PROJECT_IS_TOP_LEVEL}
            USES_TERMINAL_BUILD     ${PROJECT_IS_TOP_LEVEL}
            USES_TERMINAL_TEST      ${PROJECT_IS_TOP_LEVEL}
            USES_TERMINAL_INSTALL   ${PROJECT_IS_TOP_LEVEL}

            DOWNLOAD_EXTRACT_TIMESTAMP TRUE
            CONFIGURE_COMMAND          ""
            BUILD_COMMAND              ""
            INSTALL_COMMAND            ""
        )
        ExternalProject_Get_Property(Perl SOURCE_DIR)
        set(PERL_BIN_DIR "${SOURCE_DIR}/perl/bin")

        ExternalProject_Add(
            Nasm
            URL                        https://www.nasm.us/pub/nasm/releasebuilds/3.01/win32/nasm-3.01-win32.zip
            
            USES_TERMINAL_DOWNLOAD  ${PROJECT_IS_TOP_LEVEL}
            USES_TERMINAL_UPDATE    ${PROJECT_IS_TOP_LEVEL}
            USES_TERMINAL_PATCH     ${PROJECT_IS_TOP_LEVEL}
            USES_TERMINAL_CONFIGURE ${PROJECT_IS_TOP_LEVEL}
            USES_TERMINAL_BUILD     ${PROJECT_IS_TOP_LEVEL}
            USES_TERMINAL_TEST      ${PROJECT_IS_TOP_LEVEL}
            USES_TERMINAL_INSTALL   ${PROJECT_IS_TOP_LEVEL}

            DOWNLOAD_EXTRACT_TIMESTAMP TRUE
            CONFIGURE_COMMAND          ""
            BUILD_COMMAND              ""
            INSTALL_COMMAND            ""
        )
        ExternalProject_Get_Property(Nasm SOURCE_DIR)
        set(NASM_BIN_DIR "${SOURCE_DIR}")

        function(OPENSSL_DEPENDENCY_INJECT out_var)
            set(cmd ${ARGN})
            set(${out_var}
                ${CMAKE_COMMAND} -E env
                    --modify PATH=path_list_append:${PERL_BIN_DIR}
                    --modify PATH=path_list_append:${NASM_BIN_DIR}
                    CL=/MP
                    VSCMD_DEBUG=0
                --
                cmd /Q /C "call VsDevCmd.bat -host_arch=x86 -arch=x86 && ${cmd}"
                PARENT_SCOPE
            )
        endfunction()

        OPENSSL_DEPENDENCY_INJECT(OPENSSL_CONFIGURE_COMMAND "perl ${OPENSSL_SOURCE_DIR}/Configure VC-WIN32")
        OPENSSL_DEPENDENCY_INJECT(OPENSSL_BUILD_COMMAND     "nmake")
        OPENSSL_DEPENDENCY_INJECT(OPENSSL_TEST_COMMAND      "nmake test")
        OPENSSL_DEPENDENCY_INJECT(OPENSSL_INSTALL_COMMAND   "nmake install")
        set(OPENSSL_DEPENDENCY                              Perl Nasm)
        set(OPENSSL_CRYPTO_LIB                              "${OPENSSL_LIB_DIR}/libcrypto.lib")
        set(OPENSSL_SSL_LIB                                 "${OPENSSL_LIB_DIR}/libssl.lib")
    endif()

    # linkage flag (driven by ENCRYPTION_LINKAGE)
    if (ENCRYPTION_LINKAGE STREQUAL "DYNAMIC")
        list(APPEND OPENSSL_CONFIGURE_COMMAND shared)
    else()
        list(APPEND OPENSSL_CONFIGURE_COMMAND no-shared)
    endif()

    # Tests are only built for the top-level project to reduce build times for downstream projects that include this as a dependency.
    if (NOT PROJECT_IS_TOP_LEVEL)
        set(OPENSSL_TEST_COMMAND "")
    endif()

    # ============================================================
    # OpenSSL – ExternalProject
    # ============================================================
    ExternalProject_Add(
        OpenSSL

        DEPENDS ${OPENSSL_DEPENDENCY}

        GIT_REPOSITORY https://github.com/openssl/openssl.git
        GIT_TAG        ${OPENSSL_VERSION}

        USES_TERMINAL_DOWNLOAD  ${PROJECT_IS_TOP_LEVEL}
        USES_TERMINAL_UPDATE    ${PROJECT_IS_TOP_LEVEL}
        USES_TERMINAL_PATCH     ${PROJECT_IS_TOP_LEVEL}
        USES_TERMINAL_CONFIGURE ${PROJECT_IS_TOP_LEVEL}
        USES_TERMINAL_BUILD     ${PROJECT_IS_TOP_LEVEL}
        USES_TERMINAL_TEST      ${PROJECT_IS_TOP_LEVEL}
        USES_TERMINAL_INSTALL   ${PROJECT_IS_TOP_LEVEL}

        CONFIGURE_COMMAND
            ${OPENSSL_CONFIGURE_COMMAND}
            --libdir=lib
            --prefix=${OPENSSL_INSTALL_DIR}
            --openssldir=${OPENSSL_CONFIG_DIR}

        BUILD_COMMAND   ${OPENSSL_BUILD_COMMAND}
        TEST_COMMAND    ${OPENSSL_TEST_COMMAND}
        UPDATE_COMMAND  ""
        INSTALL_COMMAND ${OPENSSL_INSTALL_COMMAND}
    )

    # ============================================================
    # OpenSSL – IMPORTED Targets
    # (ExternalProject runs at build time, so we pre-create paths
    #  to satisfy INTERFACE_INCLUDE_DIRECTORIES at configure time)
    # ============================================================
    ExternalProject_Get_Property(OpenSSL BINARY_DIR)

    if(NOT IS_DIRECTORY ${OPENSSL_INCLUDE_DIR})
        file(MAKE_DIRECTORY ${OPENSSL_INCLUDE_DIR})
    endif()
    if(NOT EXISTS ${OPENSSL_CRYPTO_LIB})
        file(WRITE ${OPENSSL_CRYPTO_LIB} "")
    endif()
    if(NOT EXISTS ${OPENSSL_SSL_LIB})
        file(WRITE ${OPENSSL_SSL_LIB} "")
    endif()

    if (ENCRYPTION_LINKAGE STREQUAL "DYNAMIC" AND WIN32)
        # Windows DLL: IMPORTED_LOCATION = .dll, IMPORTED_IMPLIB = .lib
        add_library(OpenSSL::SSL    SHARED IMPORTED GLOBAL)
        add_library(OpenSSL::Crypto SHARED IMPORTED GLOBAL)
        set_property(TARGET OpenSSL::SSL    PROPERTY IMPORTED_LOCATION ${OPENSSL_RUNTIME_SSL_LIBS})
        set_property(TARGET OpenSSL::SSL    PROPERTY IMPORTED_IMPLIB   ${OPENSSL_SSL_LIB})
        set_property(TARGET OpenSSL::Crypto PROPERTY IMPORTED_LOCATION ${OPENSSL_RUNTIME_CRYPTO_LIBS})
        set_property(TARGET OpenSSL::Crypto PROPERTY IMPORTED_IMPLIB   ${OPENSSL_CRYPTO_LIB})
    elseif (ENCRYPTION_LINKAGE STREQUAL "DYNAMIC")
        # Linux/macOS .so: IMPORTED_LOCATION = .so (no implib)
        add_library(OpenSSL::SSL    SHARED IMPORTED GLOBAL)
        add_library(OpenSSL::Crypto SHARED IMPORTED GLOBAL)
        set_property(TARGET OpenSSL::SSL    PROPERTY IMPORTED_LOCATION ${OPENSSL_SSL_LIB})
        set_property(TARGET OpenSSL::Crypto PROPERTY IMPORTED_LOCATION ${OPENSSL_CRYPTO_LIB})
    else()
        # STATIC (.a / .lib)
        add_library(OpenSSL::SSL    STATIC IMPORTED GLOBAL)
        add_library(OpenSSL::Crypto STATIC IMPORTED GLOBAL)
        set_property(TARGET OpenSSL::SSL    PROPERTY IMPORTED_LOCATION ${OPENSSL_SSL_LIB})
        set_property(TARGET OpenSSL::Crypto PROPERTY IMPORTED_LOCATION ${OPENSSL_CRYPTO_LIB})
    endif()

    set_property(TARGET OpenSSL::SSL    PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR})
    set_property(TARGET OpenSSL::Crypto PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR})
    add_dependencies(OpenSSL::SSL    OpenSSL)
    add_dependencies(OpenSSL::Crypto OpenSSL)
endif()

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

# ============================================================
# Compiler Options
# ============================================================
if (TARGET ${SUB_PROJECT_NAME})
    target_precompile_headers(${SUB_PROJECT_NAME} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include/encryption/pch.h"
    )
    if(MSVC)
        target_compile_options(${SUB_PROJECT_NAME} PRIVATE
        /MP
        /W4              # 합리적인 모든 경고
        /WX              # 경고를 에러로 (Linux의 -Werror)
        /permissive-     # 표준 엄격 모드 (Microsoft 확장 거부)
        /w14242 /w14254 /w14263 /w14265 /w14287 /we4289
        /w14296 /w14311 /w14545 /w14546 /w14547 /w14549
        /w14555 /w14619 /w14640 /w14826 /w14905 /w14906
        /w14928
        /Zc:__cplusplus  # __cplusplus 매크로 정확히 보고
        /Zc:preprocessor # 표준 준수 전처리기
        )
    endif()
endif()

if(UNIX AND NOT APPLE AND CMAKE_BUILD_TYPE STREQUAL "Release")
    set_target_properties(${SUB_PROJECT_NAME} PROPERTIES
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH            "$ORIGIN"
        SKIP_BUILD_RPATH         FALSE
        BUILD_RPATH              "$ORIGIN"
    )
endif()

# ============================================================
# Cross-platform link options carrier
# (transitive하게 따라붙도록 INTERFACE 타겟으로 운반)
# ============================================================
if(NOT TARGET EncryptionLinkOptions)
    add_library(EncryptionLinkOptions INTERFACE)
endif()

if(NOT WIN32 AND ENCRYPTION_LINKAGE STREQUAL "STATIC")
    if(ENCRYPTION_LIBC STREQUAL "musl")
        # musl: full-static OK
        target_link_options(EncryptionLinkOptions INTERFACE -static)
        message(STATUS "Encryption linkage: STATIC (musl, full-static)")
    else()
        # 도달 시점은 ENCRYPTION_LIBC == "other" 등 (glibc는 위에서 FATAL_ERROR)
        target_link_options(EncryptionLinkOptions INTERFACE
            -static-libgcc -static-libstdc++)
        message(STATUS "Encryption linkage: STATIC (libc=${ENCRYPTION_LIBC}, runtime static)")
    endif()

    find_package(Threads REQUIRED)
    target_link_libraries(EncryptionLinkOptions INTERFACE Threads::Threads)
endif()

target_link_libraries(${SUB_PROJECT_NAME} PUBLIC EncryptionLinkOptions)

if (NOT WIN32)
    target_compile_options(
        ${SUB_PROJECT_NAME} PRIVATE
        -maes
        -msse2
        -mssse3
        -fno-exceptions -fno-rtti
    )
else()
    add_compile_options(/utf-8)
endif()

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    add_compile_options(-Wuseless-cast)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    add_compile_options(
        -Weverything
        -Wno-c++98-compat
        -Wno-c++98-compat-pedantic
        -Wno-unused-macros
        -Wno-padded
    )
endif ()

if(WIN32)
    target_link_libraries(${SUB_PROJECT_NAME} PUBLIC ws2_32)
    target_link_libraries(${SUB_PROJECT_NAME} PUBLIC crypt32)
    set_target_properties(${SUB_PROJECT_NAME} PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
else()
    add_compile_options(
        -Werror
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
        -Wshadow
        -Wundef
        -Wunreachable-code
        -Wstrict-aliasing
        -Wnull-dereference
        -Wdouble-promotion
        -Wformat=2
        -Wcast-qual
        -Wcast-align
    )
endif()

# ============================================================
# clang-tidy (Linux only)
# ============================================================
find_program(CLANG_TIDY_EXE NAMES clang-tidy)
if(CLANG_TIDY_EXE)
    set(CMAKE_CXX_CLANG_TIDY
        $<$<COMPILE_LANGUAGE:CXX>:clang-tidy;-checks=-*,google-readability-casting;-fix;-fix-errors>
    )
    if (PROJECT_IS_TOP_LEVEL AND CMAKE_EXPORT_COMPILE_COMMANDS AND NOT WIN32)
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E create_symlink
                ${CMAKE_BINARY_DIR}/compile_commands.json
                ${CMAKE_BINARY_DIR}/../compile_commands.json
    )
    endif()
endif()

# Runtime-lib copy is only needed when we built OpenSSL ourselves AND
# the build is DYNAMIC (STATIC 링크면 OpenSSL이 결과물에 묶이므로 복사 불필요).
# System OpenSSL is expected to be on the loader path already (system dirs,
# vcpkg/Conan deploy, Homebrew, Firedaemon install, etc.).
set(ENCRYPTION_NEED_OPENSSL_RUNTIME_COPY FALSE)
if(ENCRYPTION_OPENSSL_BUILD_FROM_SOURCE AND ENCRYPTION_LINKAGE STREQUAL "DYNAMIC")
    set(ENCRYPTION_NEED_OPENSSL_RUNTIME_COPY TRUE)
    set(COPY_OPENSSL_LIBS "${CMAKE_CURRENT_SOURCE_DIR}/.cmake/copy_openssl_runtime_libs.cmake")
    if(WIN32)
        set(OPENSSL_RUNTIME_LIBS_DIR "${OPENSSL_BIN_DIR}")
    else()
        set(OPENSSL_RUNTIME_LIBS_DIR "${OPENSSL_LIB_DIR}")
    endif()
endif()

# ============================================================
# Tests (top-level only)
# ============================================================
if (${PROJECT_IS_TOP_LEVEL})
    set(BUILD_TESTING ON)

    include(CTest)
    enable_testing()

    add_subdirectory(test)

    foreach(TEST_SUBDIR "test" "test/aes")
        if(ENCRYPTION_NEED_OPENSSL_RUNTIME_COPY)
            add_custom_command(TARGET ${SUB_PROJECT_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND}
                    -DOPENSSL_LIB_DIR=${OPENSSL_RUNTIME_LIBS_DIR}
                    -DDEST_DIR=$<TARGET_FILE_DIR:${SUB_PROJECT_NAME}>/${TEST_SUBDIR}
                    -P "${COPY_OPENSSL_LIBS}"
                COMMENT "Copying OpenSSL runtime libraries to ${TEST_SUBDIR} output directory"
            )
            add_custom_command(TARGET ${SUB_PROJECT_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_directory_if_different
                    "${OPENSSL_CONFIG_DIR}"
                    "$<TARGET_FILE_DIR:${SUB_PROJECT_NAME}>/${TEST_SUBDIR}/${OPENSSL_CONFIG_DIR_NAME}"
                COMMENT "Copying OpenSSL config directory to ${TEST_SUBDIR} output directory"
            )
        endif()
        # STATIC 빌드면 결과물이 .a / .lib이라 실행 디렉터리에 둘 필요 없음
        if(ENCRYPTION_LINKAGE STREQUAL "DYNAMIC")
            add_custom_command(TARGET ${SUB_PROJECT_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "$<TARGET_FILE:${SUB_PROJECT_NAME}>"
                    "${CMAKE_BINARY_DIR}/${TEST_SUBDIR}"
                COMMENT "Copying ${SUB_PROJECT_NAME} DLL/so to ${TEST_SUBDIR} output directory"
            )
        endif()
    endforeach()
endif()

# ============================================================
# Post-Build – Copy artifacts to binary root
# ============================================================
# STATIC 빌드 시엔 결과물이 .a/.lib이고, OpenSSL도 결과물에 묶여 있어 복사 불필요.
if(ENCRYPTION_LINKAGE STREQUAL "DYNAMIC")
    add_custom_command(TARGET ${SUB_PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:${SUB_PROJECT_NAME}>"
            "${CMAKE_BINARY_DIR}"
        COMMENT "Copying ${SUB_PROJECT_NAME} DLL/so to binary output directory"
    )
endif()
if(ENCRYPTION_NEED_OPENSSL_RUNTIME_COPY)
    add_custom_command(TARGET ${SUB_PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND}
            -DOPENSSL_LIB_DIR=${OPENSSL_RUNTIME_LIBS_DIR}
            -DDEST_DIR=$<TARGET_FILE_DIR:${SUB_PROJECT_NAME}>
            -P "${COPY_OPENSSL_LIBS}"
        COMMENT "Copying OpenSSL runtime libraries to binary output directory"
    )
    add_custom_command(TARGET ${SUB_PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory_if_different
            "${OPENSSL_CONFIG_DIR}"
            "$<TARGET_FILE_DIR:${SUB_PROJECT_NAME}>/${OPENSSL_CONFIG_DIR_NAME}"
       COMMENT "Copying OpenSSL config directory to binary output directory"
    )
endif()

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/.cmake/cmake_include/config.h.in" "${CMAKE_CURRENT_BINARY_DIR}/config.h" @ONLY)
target_include_directories(${SUB_PROJECT_NAME} SYSTEM PUBLIC "${CMAKE_CURRENT_BINARY_DIR}")
