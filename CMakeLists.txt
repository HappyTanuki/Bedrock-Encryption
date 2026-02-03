cmake_minimum_required (VERSION 3.16)
set(SUB_PROJECT_NAME "Encryption")
project(${SUB_PROJECT_NAME} LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT DEFINED ROOT_PROJECT_NAME)
    set(ROOT_PROJECT_NAME "Root")
    include(FetchContent)
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
    set(OPENSSL_SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/OpenSSL-src) # default path by CMake
    set(OPENSSL_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl)
    set(OPENSSL_INCLUDE_DIR ${OPENSSL_INSTALL_DIR}/include)
    set(OPENSSL_CONFIGURE_COMMAND ${OPENSSL_SOURCE_DIR}/config)

    include(ExternalProject)
    include(ProcessorCount)
    ProcessorCount(NCPU)

    if(NCPU EQUAL 0)
        set(NCPU 1)
    endif()

    if (PROJECT_IS_TOP_LEVEL)
        ExternalProject_Add(
            OpenSSL
            SOURCE_DIR ${OPENSSL_SOURCE_DIR}
            GIT_REPOSITORY https://github.com/openssl/openssl.git
            GIT_TAG openssl-3.6.1
            USES_TERMINAL_DOWNLOAD TRUE
            USES_TERMINAL_CONFIGURE TRUE
            USES_TERMINAL_BUILD TRUE
            USES_TERMINAL_INSTALL TRUE
            USES_TERMINAL_DOWNLOAD TRUE
            CONFIGURE_COMMAND
                ${OPENSSL_CONFIGURE_COMMAND}
                --prefix=${OPENSSL_INSTALL_DIR}
                --openssldir=${OPENSSL_INSTALL_DIR}
            BUILD_COMMAND make -j${NCPU}
            TEST_COMMAND ""
            UPDATE_COMMAND ""
            INSTALL_COMMAND make -j${NCPU} install
            INSTALL_DIR ${OPENSSL_INSTALL_DIR}
        )
    else ()
        ExternalProject_Add(
            OpenSSL
            SOURCE_DIR ${OPENSSL_SOURCE_DIR}
            GIT_REPOSITORY https://github.com/openssl/openssl.git
            GIT_TAG openssl-3.6.1
            CONFIGURE_COMMAND
                ${OPENSSL_CONFIGURE_COMMAND}
                --prefix=${OPENSSL_INSTALL_DIR}
                --openssldir=${OPENSSL_INSTALL_DIR}
            BUILD_COMMAND make -j${NCPU}
            TEST_COMMAND ""
            UPDATE_COMMAND ""
            INSTALL_COMMAND make -j${NCPU} install
            INSTALL_DIR ${OPENSSL_INSTALL_DIR}
        )
    endif ()

    # We cannot use find_library because ExternalProject_Add() is performed at build time.
    # And to please the property INTERFACE_INCLUDE_DIRECTORIES,
    # we make the include directory in advance.
    file(MAKE_DIRECTORY ${OPENSSL_INCLUDE_DIR})
    file(WRITE ${OPENSSL_INSTALL_DIR}/lib64/libssl.so "")
    file(WRITE ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so "")

    add_library(OpenSSL::SSL STATIC IMPORTED GLOBAL)
    set_property(TARGET OpenSSL::SSL PROPERTY IMPORTED_LOCATION ${OPENSSL_INSTALL_DIR}/lib64/libssl.so)
    set_property(TARGET OpenSSL::SSL PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR})
    add_dependencies(OpenSSL::SSL OpenSSL)

    add_library(OpenSSL::Crypto STATIC IMPORTED GLOBAL)
    set_property(TARGET OpenSSL::Crypto PROPERTY IMPORTED_LOCATION ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
    set_property(TARGET OpenSSL::Crypto PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR})
    add_dependencies(OpenSSL::Crypto OpenSSL)
endif ()

file(GLOB_RECURSE SOURCES "src/*.cc")

add_library(${SUB_PROJECT_NAME} SHARED ${SOURCES})
target_link_libraries(${SUB_PROJECT_NAME} PUBLIC ${ROOT_PROJECT_NAME}::Common)

target_link_libraries(${SUB_PROJECT_NAME} PUBLIC OpenSSL::Crypto)
target_link_libraries(${SUB_PROJECT_NAME} PUBLIC OpenSSL::SSL)

if(DEFINED ROOT_PROJECT_NAME)
    add_library(${ROOT_PROJECT_NAME}::${SUB_PROJECT_NAME} ALIAS ${SUB_PROJECT_NAME})
endif()

target_include_directories(${SUB_PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(UNIX AND NOT APPLE AND CMAKE_BUILD_TYPE STREQUAL "Release")
    set_target_properties(${SUB_PROJECT_NAME} PROPERTIES
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "$ORIGIN"
        SKIP_BUILD_RPATH FALSE
        BUILD_RPATH "$ORIGIN"
    )
endif()

target_compile_options(${SUB_PROJECT_NAME} PRIVATE -maes -msse2)

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

if (PROJECT_IS_TOP_LEVEL AND CMAKE_EXPORT_COMPILE_COMMANDS)
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

add_custom_target(third_party ALL)
add_dependencies(third_party OpenSSL)
