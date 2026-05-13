# ============================================================
# Dependencies – OpenSSL
# ============================================================
# 입력 (부모에서 정의되어 있어야 함):
#   ENCRYPTION_LINKAGE        : DYNAMIC | STATIC
#
# 출력:
#   ENCRYPTION_USE_OPENSSL                  (option)
#   ENCRYPTION_OPENSSL_SOURCE               (cache)
#   ENCRYPTION_OPENSSL_BUILD_FROM_SOURCE    (var)
#   OpenSSL::SSL, OpenSSL::Crypto           (IMPORTED targets)
#   OPENSSL_INCLUDE_DIR / OPENSSL_LIB_DIR / OPENSSL_BIN_DIR
#   OPENSSL_CONFIG_DIR / OPENSSL_CONFIG_DIR_NAME
# ============================================================
include(ExternalProject)
include(ProcessorCount)

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
    # ExternalProject의 default prefix layout(<NAME>-prefix/src/<NAME>...)에 의존하지 않도록
    # 모든 디렉터리를 명시적으로 정해 ExternalProject_Add 인자로 전달합니다.
    set(OPENSSL_CONFIG_DIR_NAME "OpenSSL-Config")
    set(OPENSSL_DIR             "${CMAKE_CURRENT_BINARY_DIR}/OpenSSL")
    set(OPENSSL_SOURCE_DIR      "${OPENSSL_DIR}/source")
    set(OPENSSL_BUILD_DIR       "${OPENSSL_DIR}/build")
    set(OPENSSL_STAMP_DIR       "${OPENSSL_DIR}/stamp")
    set(OPENSSL_INSTALL_DIR     "${OPENSSL_DIR}/install")
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
    else()
        set(OPENSSL_RUNTIME_LIBS
            "${OPENSSL_BIN_DIR}/libcrypto-3-x64.dll"
            "${OPENSSL_BIN_DIR}/libssl-3-x64.dll"
        )
        set(OPENSSL_RUNTIME_CRYPTO_LIBS "${OPENSSL_BIN_DIR}/libcrypto-3-x64.dll")
        set(OPENSSL_RUNTIME_SSL_LIBS    "${OPENSSL_BIN_DIR}/libssl-3-x64.dll")
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
    set(OPENSSL_INSTALL_COMMAND   "")

    if(NOT WIN32)
        # ---- Linux / macOS ----
        set(OPENSSL_CONFIGURE_COMMAND "${OPENSSL_SOURCE_DIR}/config")
        set(OPENSSL_BUILD_COMMAND     make -j${NCPU})
        set(OPENSSL_INSTALL_COMMAND   make -j${NCPU} install)
        if(ENCRYPTION_LINKAGE STREQUAL "DYNAMIC")
            set(OPENSSL_CRYPTO_LIB    "${OPENSSL_LIB_DIR}/libcrypto.so")
            set(OPENSSL_SSL_LIB       "${OPENSSL_LIB_DIR}/libssl.so")
        else()
            set(OPENSSL_CRYPTO_LIB    "${OPENSSL_LIB_DIR}/libcrypto.a")
            set(OPENSSL_SSL_LIB       "${OPENSSL_LIB_DIR}/libssl.a")
        endif()
    else()
        # ---- Windows (x64) ----
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

        # jom: NMAKE 호환 + -j 지원 (Qt 배포). jom 바이너리 자체는 32-bit이지만 cross-bit 실행 가능.
        ExternalProject_Add(
            Jom
            URL                        https://download.qt.io/official_releases/jom/jom_1_1_4.zip

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
        ExternalProject_Get_Property(Jom SOURCE_DIR)
        set(JOM_BIN_DIR "${SOURCE_DIR}")

        function(OPENSSL_DEPENDENCY_INJECT out_var)
            set(cmd ${ARGN})
            set(${out_var}
                ${CMAKE_COMMAND} -E env
                    --modify PATH=path_list_append:${PERL_BIN_DIR}
                    --modify PATH=path_list_append:${NASM_BIN_DIR}
                    --modify PATH=path_list_append:${JOM_BIN_DIR}
                    # /FS: jom 병렬 빌드 시 여러 cl이 같은 PDB(ossl_static.pdb)에 쓰는 충돌(C1041)을 막음
                    CL=/FS
                    VSCMD_DEBUG=0
                --
                cmd /Q /C "call VsDevCmd.bat -host_arch=amd64 -arch=amd64 && ${cmd}"
                PARENT_SCOPE
            )
        endfunction()

        OPENSSL_DEPENDENCY_INJECT(OPENSSL_CONFIGURE_COMMAND "perl ${OPENSSL_SOURCE_DIR}/Configure VC-WIN64A")
        OPENSSL_DEPENDENCY_INJECT(OPENSSL_BUILD_COMMAND     "jom -j${NCPU}")
        # install은 단일 잡: docs 복사 중 다른 워커의 makefile auto-regen이 rename 충돌(Permission denied)을 유발
        OPENSSL_DEPENDENCY_INJECT(OPENSSL_INSTALL_COMMAND   "jom -j1 install")
        set(OPENSSL_DEPENDENCY                              Perl Nasm Jom)
        set(OPENSSL_CRYPTO_LIB                              "${OPENSSL_LIB_DIR}/libcrypto.lib")
        set(OPENSSL_SSL_LIB                                 "${OPENSSL_LIB_DIR}/libssl.lib")
    endif()

    # linkage flag (driven by ENCRYPTION_LINKAGE)
    if (ENCRYPTION_LINKAGE STREQUAL "DYNAMIC")
        list(APPEND OPENSSL_CONFIGURE_COMMAND shared)
    else()
        list(APPEND OPENSSL_CONFIGURE_COMMAND no-shared)
    endif()

    # OpenSSL 자체 test/app 바이너리는 빌드하지 않는다.
    # - 본 프로젝트는 OpenSSL 라이브러리만 사용 (CLI/test 불필요)
    # - jom 병렬 빌드 시 test 링크가 LNK4099(app.pdb)로 시끄러움
    # - install 단계의 build_inst_programs가 makefile auto-regen rename 충돌(Error 13)을 유발
    # - 빌드 시간/디스크 절약
    list(APPEND OPENSSL_CONFIGURE_COMMAND no-tests no-apps)
    set(OPENSSL_TEST_COMMAND "")

    # Windows: 한글 코드페이지(CP949) 환경에서 OpenSSL 일부 .c가 비-ASCII 문자를
    # 포함해 C4819를 일으킴. cl의 source/execution 인코딩을 UTF-8로 명시.
    if(WIN32)
        list(APPEND OPENSSL_CONFIGURE_COMMAND /utf-8)
    endif()

    # ============================================================
    # OpenSSL – ExternalProject
    # ============================================================
    ExternalProject_Add(
        OpenSSL

        DEPENDS ${OPENSSL_DEPENDENCY}

        # Paths (ExternalProject default layout 의존 제거)
        PREFIX      ${OPENSSL_DIR}
        SOURCE_DIR  ${OPENSSL_SOURCE_DIR}
        BINARY_DIR  ${OPENSSL_BUILD_DIR}
        STAMP_DIR   ${OPENSSL_STAMP_DIR}
        INSTALL_DIR ${OPENSSL_INSTALL_DIR}

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
        TEST_COMMAND    ""
        UPDATE_COMMAND  ""
        INSTALL_COMMAND ${OPENSSL_INSTALL_COMMAND}
    )

    # ============================================================
    # OpenSSL – IMPORTED Targets
    # (ExternalProject runs at build time, so we pre-create paths
    #  to satisfy INTERFACE_INCLUDE_DIRECTORIES at configure time)
    # ============================================================
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
