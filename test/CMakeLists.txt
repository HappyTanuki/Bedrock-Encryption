file(GLOB TEST_SOURCES "*.cc")

foreach(test_src ${TEST_SOURCES})
    get_filename_component(test_name ${test_src} NAME_WE)
    add_executable(${test_name} ${test_src})

    if(UNIX AND NOT APPLE AND CMAKE_BUILD_TYPE STREQUAL "Release")
        set_target_properties(${test_name} PROPERTIES
            BUILD_WITH_INSTALL_RPATH TRUE
            INSTALL_RPATH "$ORIGIN"
            SKIP_BUILD_RPATH FALSE
            BUILD_RPATH "$ORIGIN"
        )
    endif()

    target_link_libraries(${test_name} PRIVATE ${PROJECT_NAME})
    if(NOT WIN32)
        target_compile_options(${test_name} PRIVATE -maes -msse2)
    endif()
    add_test(NAME ${test_name} COMMAND ${test_name})
    set_tests_properties(${test_name} PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
endforeach()

add_custom_target(copy_test_vectors ALL
    COMMAND ${CMAKE_COMMAND} -E echo "Running post build test vector copy"
    COMMAND ${CMAKE_COMMAND} -E make_directory
            ${CMAKE_CURRENT_BINARY_DIR}/test_vector
    COMMAND ${CMAKE_COMMAND} -E copy_directory_if_different
            ${CMAKE_CURRENT_SOURCE_DIR}/test_vector
            ${CMAKE_CURRENT_BINARY_DIR}/test_vector
    COMMENT "Copying test vector to output directory"
)

add_subdirectory(aes)