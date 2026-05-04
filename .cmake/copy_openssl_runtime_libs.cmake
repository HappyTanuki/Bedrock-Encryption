if (NOT OPENSSL_LIB_DIR)
    message(STATUS "OPENSSL_LIB_DIR is not set")
else()
    file(GLOB OPENSSL_LIBS
        "${OPENSSL_LIB_DIR}/libssl.so*"
        "${OPENSSL_LIB_DIR}/libcrypto.so*"
        "${OPENSSL_LIB_DIR}/libssl.a*"
        "${OPENSSL_LIB_DIR}/libcrypto.a*"
        "${OPENSSL_LIB_DIR}/libssl*.dll"
        "${OPENSSL_LIB_DIR}/libcrypto*.dll"
    )

    foreach(f ${OPENSSL_LIBS})
        get_filename_component(name "${f}" NAME)

        if(IS_SYMLINK "${f}")
            # 링크 대상 알아내기
            file(READ_SYMLINK "${f}" link_target)

            # 목적지에 심볼릭 링크 생성
            file(CREATE_LINK
                "${link_target}"
                "${DEST_DIR}/${name}"
                SYMBOLIC
            )
        else()
            # 실파일은 그대로 복사
            file(COPY "${f}" DESTINATION "${DEST_DIR}")
        endif()
    endforeach()
endif()