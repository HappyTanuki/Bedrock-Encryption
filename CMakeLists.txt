cmake_minimum_required (VERSION 3.25)

# ============================================================
# Policy
# ============================================================
if(WIN32 AND POLICY CMP0091)
    cmake_policy(SET CMP0091 NEW)
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

# ============================================================
# Dependencies – Common
# ============================================================
include(FetchContent)
include(ExternalProject)
include(ProcessorCount)

if(NOT DEFINED ROOT_PROJECT_NAME)
    set(ROOT_PROJECT_NAME "Root")
endif()

FetchContent_Declare(
    Common
    GIT_REPOSITORY https://github.com/HappyTanuki/Bedrock-Common.git
    GIT_TAG        master
    GIT_SHALLOW    ON
)
FetchContent_MakeAvailable(Common)

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
elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
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
    set(OPENSSL_BUILD_COMMAND     "make -j${NCPU}")
    set(OPENSSL_TEST_COMMAND      "make -j${NCPU} test")
    set(OPENSSL_INSTALL_COMMAND   "make -j${NCPU} install")
    set(OPENSSL_CRYPTO_LIB        "${OPENSSL_LIB_DIR}/libcrypto.so")
    set(OPENSSL_SSL_LIB           "${OPENSSL_LIB_DIR}/libssl.so")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 8 AND WIN32)
    # ---- Windows 64-bit ----
    ExternalProject_Add(
        Perl
        URL                        https://github.com/StrawberryPerl/Perl-Dist-Strawberry/releases/download/SP_54201_64bit/strawberry-perl-5.42.0.1-64bit-portable.zip

        USES_TERMINAL_DOWNLOAD     ${PROJECT_IS_TOP_LEVEL}
        USES_TERMINAL_CONFIGURE    ${PROJECT_IS_TOP_LEVEL}
        USES_TERMINAL_BUILD        ${PROJECT_IS_TOP_LEVEL}
        USES_TERMINAL_TEST         ${PROJECT_IS_TOP_LEVEL}
        USES_TERMINAL_INSTALL      ${PROJECT_IS_TOP_LEVEL}

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

        USES_TERMINAL_DOWNLOAD     ${PROJECT_IS_TOP_LEVEL}
        USES_TERMINAL_CONFIGURE    ${PROJECT_IS_TOP_LEVEL}
        USES_TERMINAL_BUILD        ${PROJECT_IS_TOP_LEVEL}
        USES_TERMINAL_TEST         ${PROJECT_IS_TOP_LEVEL}
        USES_TERMINAL_INSTALL      ${PROJECT_IS_TOP_LEVEL}

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

        USES_TERMINAL_DOWNLOAD     ${PROJECT_IS_TOP_LEVEL}
        USES_TERMINAL_CONFIGURE    ${PROJECT_IS_TOP_LEVEL}
        USES_TERMINAL_BUILD        ${PROJECT_IS_TOP_LEVEL}
        USES_TERMINAL_TEST         ${PROJECT_IS_TOP_LEVEL}
        USES_TERMINAL_INSTALL      ${PROJECT_IS_TOP_LEVEL}

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

        USES_TERMINAL_DOWNLOAD     ${PROJECT_IS_TOP_LEVEL}
        USES_TERMINAL_CONFIGURE    ${PROJECT_IS_TOP_LEVEL}
        USES_TERMINAL_BUILD        ${PROJECT_IS_TOP_LEVEL}
        USES_TERMINAL_TEST         ${PROJECT_IS_TOP_LEVEL}
        USES_TERMINAL_INSTALL      ${PROJECT_IS_TOP_LEVEL}

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

# linkage flag
if (CMAKE_MSVC_RUNTIME_LIBRARY MATCHES "DLL$")
    list(APPEND OPENSSL_CONFIGURE_COMMAND shared)
else()
    list(APPEND OPENSSL_CONFIGURE_COMMAND no-shared)
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

ExternalProject_Add_Step(OpenSSL pre_build_log
    COMMAND ${CMAKE_COMMAND} -E echo "Building OpenSSL..."
    DEPENDEES configure
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

if (CMAKE_MSVC_RUNTIME_LIBRARY MATCHES "DLL$")
    add_library(OpenSSL::SSL    SHARED IMPORTED GLOBAL)
    add_library(OpenSSL::Crypto SHARED IMPORTED GLOBAL)
    set_property(TARGET OpenSSL::SSL    PROPERTY IMPORTED_LOCATION ${OPENSSL_RUNTIME_SSL_LIBS})
    set_property(TARGET OpenSSL::SSL    PROPERTY IMPORTED_IMPLIB   ${OPENSSL_SSL_LIB})
    set_property(TARGET OpenSSL::Crypto PROPERTY IMPORTED_LOCATION ${OPENSSL_RUNTIME_CRYPTO_LIBS})
    set_property(TARGET OpenSSL::Crypto PROPERTY IMPORTED_IMPLIB   ${OPENSSL_CRYPTO_LIB})
else()
    add_library(OpenSSL::SSL    STATIC IMPORTED GLOBAL)
    add_library(OpenSSL::Crypto STATIC IMPORTED GLOBAL)
    set_property(TARGET OpenSSL::SSL    PROPERTY IMPORTED_LOCATION ${OPENSSL_SSL_LIB})
    set_property(TARGET OpenSSL::Crypto PROPERTY IMPORTED_LOCATION ${OPENSSL_CRYPTO_LIB})
endif()

set_property(TARGET OpenSSL::SSL    PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR})
set_property(TARGET OpenSSL::Crypto PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR})
add_dependencies(OpenSSL::SSL    OpenSSL)
add_dependencies(OpenSSL::Crypto OpenSSL)

# ============================================================
# Target – Encryption
# ============================================================
file(GLOB_RECURSE SOURCES "src/*.cc")

if (CMAKE_MSVC_RUNTIME_LIBRARY MATCHES "DLL$")
    add_library(${SUB_PROJECT_NAME} SHARED ${SOURCES})
else ()
    add_library(${SUB_PROJECT_NAME} STATIC ${SOURCES})
endif ()

target_link_libraries(${SUB_PROJECT_NAME} PUBLIC ${ROOT_PROJECT_NAME}::Common)
target_link_libraries(${SUB_PROJECT_NAME} PUBLIC OpenSSL::Crypto)
target_link_libraries(${SUB_PROJECT_NAME} PUBLIC OpenSSL::SSL)

target_include_directories(${SUB_PROJECT_NAME} SYSTEM PUBLIC "${OPENSSL_INCLUDE_DIR}")
target_include_directories(${SUB_PROJECT_NAME}        PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

# Alias for parent projects
if(DEFINED ROOT_PROJECT_NAME)
    add_library(${ROOT_PROJECT_NAME}::${SUB_PROJECT_NAME} ALIAS ${SUB_PROJECT_NAME})
endif()

# ============================================================
# Compiler Options
# ============================================================
if (TARGET ${SUB_PROJECT_NAME})
    target_precompile_headers(${SUB_PROJECT_NAME} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include/encryption/pch.h"
    )
    if(MSVC)
        target_compile_options(${SUB_PROJECT_NAME} PRIVATE /MP)
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

set(COPY_OPENSSL_LIBS "${CMAKE_CURRENT_SOURCE_DIR}/.cmake/copy_openssl_runtime_libs.cmake")
if(WIN32)
    set(OPENSSL_RUNTIME_LIBS_DIR "${OPENSSL_BIN_DIR}")
else()
    set(OPENSSL_RUNTIME_LIBS_DIR "${OPENSSL_LIB_DIR}")
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
        add_custom_command(TARGET ${SUB_PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND}
                -DOPENSSL_LIB_DIR=${OPENSSL_RUNTIME_LIBS_DIR}
                -DDEST_DIR=$<TARGET_FILE_DIR:${SUB_PROJECT_NAME}>/${TEST_SUBDIR}
                -P "${COPY_OPENSSL_LIBS}"
            COMMENT "Copying OpenSSL runtime libraries to ${TEST_SUBDIR} output directory"
        )
        add_custom_command(TARGET ${SUB_PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "$<TARGET_FILE:${SUB_PROJECT_NAME}>"
                "${CMAKE_BINARY_DIR}/${TEST_SUBDIR}"
            COMMENT "Copying ${SUB_PROJECT_NAME} DLL/so to ${TEST_SUBDIR} output directory"
        )
        add_custom_command(TARGET ${SUB_PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_directory_if_different
                "${OPENSSL_CONFIG_DIR}"
                "$<TARGET_FILE_DIR:${SUB_PROJECT_NAME}>/${TEST_SUBDIR}/${OPENSSL_CONFIG_DIR_NAME}"
            COMMENT "Copying OpenSSL config directory to ${TEST_SUBDIR} output directory"
        )
    endforeach()
endif()

# ============================================================
# Post-Build – Copy artifacts to binary root
# ============================================================
add_custom_command(TARGET ${SUB_PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_FILE:${SUB_PROJECT_NAME}>"
        "${CMAKE_BINARY_DIR}"
    COMMENT "Copying ${SUB_PROJECT_NAME} DLL/so to binary output directory"
)
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
