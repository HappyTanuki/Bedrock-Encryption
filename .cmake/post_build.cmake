# ============================================================
# Post-Build – Test directory copies + final artifact copies
# ============================================================
# 입력:
#   SUB_PROJECT_NAME
#   ENCRYPTION_LINKAGE
#   ENCRYPTION_OPENSSL_BUILD_FROM_SOURCE
#   OPENSSL_BIN_DIR / OPENSSL_LIB_DIR / OPENSSL_CONFIG_DIR / OPENSSL_CONFIG_DIR_NAME
# 출력:
#   ENCRYPTION_NEED_OPENSSL_RUNTIME_COPY  (var)
# ============================================================

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
