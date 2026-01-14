file(GLOB TEST_SOURCES "*.cc")

foreach(test_src ${TEST_SOURCES})
    get_filename_component(test_name ${test_src} NAME_WE)
    add_executable(${test_name} ${test_src})
    target_link_libraries(${test_name} PRIVATE ${PROJECT_NAME})
    if(NOT WIN32)
        target_compile_options(${test_name} PRIVATE -maes -msse2)
    endif()
    message(STATUS "adding test: ${test_src}")
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