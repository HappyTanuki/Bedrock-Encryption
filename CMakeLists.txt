cmake_minimum_required (VERSION 3.25)
set(SUB_PROJECT_NAME "Encryption")
project(${SUB_PROJECT_NAME} LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

if(NOT DEFINED ROOT_PROJECT_NAME)
    set(ROOT_PROJECT_NAME "Root")
    FetchContent_Declare(
        Common
        GIT_REPOSITORY https://github.com/HappyTanuki/Bedrock-Common.git
        GIT_TAG master
        GIT_SHALLOW ON
    )
    FetchContent_MakeAvailable(Common)
endif()

# find_package(OpenSSL REQUIRED)
set(OpenSSL_FOUND false)

if (NOT OpenSSL_FOUND)
    include(ExternalProject)
    include(ProcessorCount)
    ProcessorCount(NCPU)

    if(NCPU EQUAL 0)
        set(NCPU 1)
    endif()

    if(NOT WIN32)
        ExternalProject_Add(
            OpenSSL

            GIT_REPOSITORY https://github.com/openssl/openssl.git
            GIT_TAG openssl-3.6.1

            USES_TERMINAL_DOWNLOAD TRUE
            USES_TERMINAL_CONFIGURE TRUE
            USES_TERMINAL_BUILD TRUE
            USES_TERMINAL_INSTALL TRUE

            CONFIGURE_COMMAND
                <SOURCE_DIR>/config
                --prefix=<BINARY_DIR>/../OpenSSL-Install
                --openssldir=<BINARY_DIR>/../OpenSSL-Config

            BUILD_COMMAND make -j${NCPU}
            TEST_COMMAND ""
            UPDATE_COMMAND ""
            INSTALL_COMMAND make -j${NCPU} install
        )
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 8 AND WIN32)
        ExternalProject_Add(
            Perl
            URL https://github.com/StrawberryPerl/Perl-Dist-Strawberry/releases/download/SP_54201_64bit/strawberry-perl-5.42.0.1-64bit-portable.zip
            DOWNLOAD_EXTRACT_TIMESTAMP TRUE
            CONFIGURE_COMMAND ""
            BUILD_COMMAND ""
            INSTALL_COMMAND ""
        )
        ExternalProject_Get_Property(Perl SOURCE_DIR)
        set(PERL_BIN_DIR "${SOURCE_DIR}/perl/bin")
        ExternalProject_Add(
            Nasm
            URL https://www.nasm.us/pub/nasm/releasebuilds/3.01/win64/nasm-3.01-win64.zip
            DOWNLOAD_EXTRACT_TIMESTAMP TRUE
            CONFIGURE_COMMAND ""
            BUILD_COMMAND ""
            INSTALL_COMMAND ""
        )
        ExternalProject_Get_Property(Nasm SOURCE_DIR)
        set(NASM_BIN_DIR "${SOURCE_DIR}")

        ExternalProject_Add(
            OpenSSL
            
            DEPENDS Perl Nasm

            GIT_REPOSITORY https://github.com/openssl/openssl.git
            GIT_TAG openssl-3.6.1

            USES_TERMINAL_DOWNLOAD TRUE
            USES_TERMINAL_CONFIGURE TRUE
            USES_TERMINAL_BUILD TRUE
            USES_TERMINAL_INSTALL TRUE

            CONFIGURE_COMMAND
                ${CMAKE_COMMAND} -E env --modify PATH=path_list_append:${PERL_BIN_DIR} --modify PATH=path_list_append:${NASM_BIN_DIR} --
                perl ../OpenSSL/Configure VC-WIN64A
                --prefix=<BINARY_DIR>/../OpenSSL-Install
                --openssldir=<BINARY_DIR>/../OpenSSL-Config

            BUILD_COMMAND
                ${CMAKE_COMMAND} -E env --modify PATH=path_list_append:${PERL_BIN_DIR} --modify PATH=path_list_append:${NASM_BIN_DIR} CL=/MP --
                cmd /C "call VsDevCmd.bat -host_arch=amd64 -arch=amd64 && nmake"

            TEST_COMMAND ""
            UPDATE_COMMAND ""

            INSTALL_COMMAND
                ${CMAKE_COMMAND} -E env --modify PATH=path_list_append:${PERL_BIN_DIR} --modify PATH=path_list_append:${NASM_BIN_DIR} CL=/MP --
                cmd /C "call VsDevCmd.bat -host_arch=amd64 -arch=amd64 && nmake install"
        )
    else()
        ExternalProject_Add(
            Perl
            URL https://strawberryperl.com/download/5.32.1.1/strawberry-perl-no64-5.32.1.1-32bit-portable.zip
            DOWNLOAD_EXTRACT_TIMESTAMP TRUE
            CONFIGURE_COMMAND ""
            BUILD_COMMAND ""
            INSTALL_COMMAND ""
        )
        ExternalProject_Get_Property(Perl SOURCE_DIR)
        set(PERL_BIN_DIR "${SOURCE_DIR}/perl/bin")
        ExternalProject_Add(
            Nasm
            URL https://www.nasm.us/pub/nasm/releasebuilds/3.01/win32/nasm-3.01-win32.zip
            DOWNLOAD_EXTRACT_TIMESTAMP TRUE
            CONFIGURE_COMMAND ""
            BUILD_COMMAND ""
            INSTALL_COMMAND ""
        )
        ExternalProject_Get_Property(Nasm SOURCE_DIR)
        set(NASM_BIN_DIR "${SOURCE_DIR}")

        ExternalProject_Add(
            OpenSSL
            
            DEPENDS Perl Nasm

            GIT_REPOSITORY https://github.com/openssl/openssl.git
            GIT_TAG openssl-3.6.1

            USES_TERMINAL_DOWNLOAD TRUE
            USES_TERMINAL_CONFIGURE TRUE
            USES_TERMINAL_BUILD TRUE
            USES_TERMINAL_INSTALL TRUE

            CONFIGURE_COMMAND
                ${CMAKE_COMMAND} -E env --modify PATH=path_list_append:${PERL_BIN_DIR} --modify PATH=path_list_append:${NASM_BIN_DIR} --
                perl ../OpenSSL/Configure VC-WIN32
                --prefix=<BINARY_DIR>/../OpenSSL-Install
                --openssldir=<BINARY_DIR>/../OpenSSL-Config

            BUILD_COMMAND
                ${CMAKE_COMMAND} -E env --modify PATH=path_list_append:${PERL_BIN_DIR} --modify PATH=path_list_append:${NASM_BIN_DIR} CL=/MP --
                cmd /C "call VsDevCmd.bat -host_arch=x86 -arch=x86 && nmake"

            TEST_COMMAND ""
            UPDATE_COMMAND ""

            INSTALL_COMMAND
                ${CMAKE_COMMAND} -E env --modify PATH=path_list_append:${PERL_BIN_DIR} --modify PATH=path_list_append:${NASM_BIN_DIR} CL=/MP --
                cmd /C "call VsDevCmd.bat -host_arch=x86 -arch=x86 && nmake install"
        )
    endif()

    # We cannot use find_library because ExternalProject_Add() is performed at build time.
    # And to please the property INTERFACE_INCLUDE_DIRECTORIES,
    # we make the include directory in advance.
    ExternalProject_Get_Property(OpenSSL BINARY_DIR)
    if(NOT IS_DIRECTORY ${BINARY_DIR}/../OpenSSL-Install/include/openssl)
        file(MAKE_DIRECTORY ${BINARY_DIR}/../OpenSSL-Install/include/openssl)
    endif()

    add_library(OpenSSL::SSL STATIC IMPORTED GLOBAL)
    set_property(TARGET OpenSSL::SSL PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${BINARY_DIR}/../OpenSSL-Install/include/openssl)
    add_dependencies(OpenSSL::SSL OpenSSL)

    add_library(OpenSSL::Crypto STATIC IMPORTED GLOBAL)
    set_property(TARGET OpenSSL::Crypto PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${BINARY_DIR}/../OpenSSL-Install/include/openssl)
    add_dependencies(OpenSSL::Crypto OpenSSL)

    if (CMAKE_SIZEOF_VOID_P EQUAL 8 AND NOT WIN32)
        if(NOT EXISTS ${BINARY_DIR}/../OpenSSL-Install/lib64/libssl.so)
            file(WRITE ${BINARY_DIR}/../OpenSSL-Install/lib64/libssl.so "")
        endif()
        if(NOT EXISTS ${BINARY_DIR}/../OpenSSL-Install/lib64/libcrypto.so)
            file(WRITE ${BINARY_DIR}/../OpenSSL-Install/lib64/libcrypto.so "")
        endif()
        set_property(TARGET OpenSSL::SSL PROPERTY IMPORTED_LOCATION ${BINARY_DIR}/../OpenSSL-Install/lib64/libssl.so)
        set_property(TARGET OpenSSL::Crypto PROPERTY IMPORTED_LOCATION ${BINARY_DIR}/../OpenSSL-Install/lib64/libcrypto.so)
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 4 AND NOT WIN32)
        if(NOT EXISTS ${BINARY_DIR}/../OpenSSL-Install/lib/libssl.so)
            file(WRITE ${BINARY_DIR}/../OpenSSL-Install/lib/libssl.so "")
        endif()
        if(NOT EXISTS ${BINARY_DIR}/../OpenSSL-Install/lib/libcrypto.so)
            file(WRITE ${BINARY_DIR}/../OpenSSL-Install/lib/libcrypto.so "")
        endif()
        set_property(TARGET OpenSSL::SSL PROPERTY IMPORTED_LOCATION ${BINARY_DIR}/../OpenSSL-Install/lib/libssl.so)
        set_property(TARGET OpenSSL::Crypto PROPERTY IMPORTED_LOCATION ${BINARY_DIR}/../OpenSSL-Install/lib/libcrypto.so)
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 8 AND WIN32)
        set(OPENSSL_CRYPTO ${BINARY_DIR}/../OpenSSL-Install/bin/libcrypto-3-x64.dll)
        set(OPENSSL_SSL ${BINARY_DIR}/../OpenSSL-Install/bin/libssl-3-x64.dll)
        
        if(NOT EXISTS ${BINARY_DIR}/../OpenSSL-Install/lib/libssl.lib)
            file(WRITE ${BINARY_DIR}/../OpenSSL-Install/lib/libssl.lib "")
        endif()
        if(NOT EXISTS ${BINARY_DIR}/../OpenSSL-Install/lib/libcrypto.lib)
            file(WRITE ${BINARY_DIR}/../OpenSSL-Install/lib/libcrypto.lib "")
        endif()
        set_property(TARGET OpenSSL::SSL PROPERTY IMPORTED_LOCATION ${BINARY_DIR}/../OpenSSL-Install/lib/libssl.lib)
        set_property(TARGET OpenSSL::Crypto PROPERTY IMPORTED_LOCATION ${BINARY_DIR}/../OpenSSL-Install/lib/libcrypto.lib)
    else()
        set(OPENSSL_CRYPTO ${BINARY_DIR}/../OpenSSL-Install/bin/libcrypto-3.dll)
        set(OPENSSL_SSL ${BINARY_DIR}/../OpenSSL-Install/bin/libssl-3.dll)

        if(NOT EXISTS ${BINARY_DIR}/../OpenSSL-Install/lib/libssl.lib)
            file(WRITE ${BINARY_DIR}/../OpenSSL-Install/lib/libssl.lib "")
        endif()
        if(NOT EXISTS ${BINARY_DIR}/../OpenSSL-Install/lib/libcrypto.lib)
            file(WRITE ${BINARY_DIR}/../OpenSSL-Install/lib/libcrypto.lib "")
        endif()
        set_property(TARGET OpenSSL::SSL PROPERTY IMPORTED_LOCATION ${BINARY_DIR}/../OpenSSL-Install/lib/libssl.lib)
        set_property(TARGET OpenSSL::Crypto PROPERTY IMPORTED_LOCATION ${BINARY_DIR}/../OpenSSL-Install/lib/libcrypto.lib)
    endif()
endif()

file(GLOB_RECURSE SOURCES "src/*.cc")

add_library(${SUB_PROJECT_NAME} SHARED ${SOURCES})
target_link_libraries(${SUB_PROJECT_NAME} PUBLIC ${ROOT_PROJECT_NAME}::Common)

target_link_libraries(${SUB_PROJECT_NAME} PUBLIC OpenSSL::Crypto)
target_link_libraries(${SUB_PROJECT_NAME} PUBLIC OpenSSL::SSL)

if(DEFINED ROOT_PROJECT_NAME)
    add_library(${ROOT_PROJECT_NAME}::${SUB_PROJECT_NAME} ALIAS ${SUB_PROJECT_NAME})
endif()

ExternalProject_Get_Property(OpenSSL BINARY_DIR)
target_include_directories(${SUB_PROJECT_NAME} PUBLIC ${BINARY_DIR}/../OpenSSL-Install/include)
target_include_directories(${SUB_PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(UNIX AND NOT APPLE AND CMAKE_BUILD_TYPE STREQUAL "Release")
    set_target_properties(${SUB_PROJECT_NAME} PROPERTIES
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "$ORIGIN"
        SKIP_BUILD_RPATH FALSE
        BUILD_RPATH "$ORIGIN"
    )
endif()

if (NOT WIN32)
    target_compile_options(${SUB_PROJECT_NAME} PRIVATE -maes -msse2)
else()
    add_compile_options(/utf-8)
endif()

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    # Additional flags for GCC
    add_compile_options(-Wuseless-cast)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    # Additional flags for Clang
    add_compile_options(-Weverything -Wno-c++98-compat -Wno-c++98-compat-pedantic -Wno-unused-macros -Wno-padded)
endif ()
if(WIN32)
    target_link_libraries(${SUB_PROJECT_NAME} PUBLIC ws2_32)
    set_target_properties(${SUB_PROJECT_NAME} PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
else()
    add_compile_options(-Werror -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Wundef -Wunreachable-code -Wstrict-aliasing -Wnull-dereference -Wdouble-promotion -Wformat=2 -Wcast-qual -Wcast-align)
endif()

find_program(CLANG_TIDY_EXE NAMES clang-tidy)

if(CLANG_TIDY_EXE)
    set(CMAKE_CXX_CLANG_TIDY
    $<$<COMPILE_LANGUAGE:CXX>:clang-tidy;-checks=-*,google-readability-casting;-fix;-fix-errors>
)
endif()

if (PROJECT_IS_TOP_LEVEL AND CMAKE_EXPORT_COMPILE_COMMANDS AND NOT WIN32)
  execute_process(
    COMMAND ${CMAKE_COMMAND} -E create_symlink
            ${CMAKE_BINARY_DIR}/compile_commands.json
            ${CMAKE_BINARY_DIR}/../compile_commands.json
  )
endif()

option(BEDROCK_NETWORKING_BUILD_TESTS
  "Build Bedrock tests"
  ${PROJECT_IS_TOP_LEVEL}
)

if (BEDROCK_NETWORKING_BUILD_TESTS)
  set(BUILD_TESTING ON)

  include(CTest)
  enable_testing()

  add_subdirectory(test)
endif()

add_custom_command(TARGET ${SUB_PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_FILE:${SUB_PROJECT_NAME}>"
        "${CMAKE_BINARY_DIR}/test"
    COMMENT "Copying ${SUB_PROJECT_NAME} DLL/so to test output directory"
)
add_custom_command(TARGET ${SUB_PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_FILE:${SUB_PROJECT_NAME}>"
        "${CMAKE_BINARY_DIR}/test/aes"
    COMMENT "Copying ${SUB_PROJECT_NAME} DLL/so to aes test output directory"
)

add_custom_command(TARGET ${SUB_PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${OPENSSL_CRYPTO}
        "$<TARGET_FILE_DIR:${SUB_PROJECT_NAME}>"
    COMMENT "Copying OpenSSL::Crypto DLL/so to output directory"
)
add_custom_command(TARGET ${SUB_PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${OPENSSL_CRYPTO}
        "$<TARGET_FILE_DIR:${SUB_PROJECT_NAME}>/test"
    COMMENT "Copying OpenSSL::Crypto DLL/so to test output directory"
)
add_custom_command(TARGET ${SUB_PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${OPENSSL_CRYPTO}
        "$<TARGET_FILE_DIR:${SUB_PROJECT_NAME}>/test/aes"
    COMMENT "Copying OpenSSL::Crypto DLL/so to aes test output directory"
)
add_custom_command(TARGET ${SUB_PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${OPENSSL_SSL}
        "$<TARGET_FILE_DIR:${SUB_PROJECT_NAME}>"
    COMMENT "Copying OpenSSL::SSL DLL/so to output directory"
)
add_custom_command(TARGET ${SUB_PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${OPENSSL_SSL}
        "$<TARGET_FILE_DIR:${SUB_PROJECT_NAME}>/test"
    COMMENT "Copying OpenSSL::SSL DLL/so to test output directory"
)
add_custom_command(TARGET ${SUB_PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${OPENSSL_SSL}
        "$<TARGET_FILE_DIR:${SUB_PROJECT_NAME}>/test/aes"
    COMMENT "Copying OpenSSL::SSL DLL/so to aes test output directory"
)
add_custom_command(TARGET ${SUB_PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_FILE:${SUB_PROJECT_NAME}>"
        "$<TARGET_FILE_DIR:${SUB_PROJECT_NAME}>"
    COMMENT "Copying this DLL/so to output directory"
)
