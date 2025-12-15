
set(EXEC_NAME "schc-demo-app")
set(UTILS "utils-lib")
set(LOGGER_LIB "logger-lib")
set(CLI_LIB "cli-lib")
set(AHOI_SERVICE "ahoi-service-lib")
set(SCHC_SERVICE "schc-service-lib")
set(SENSOR_SERVICE "sensor-service-lib")

add_library(${UTILS} OBJECT "utils.c")
target_include_directories(${UTILS} PRIVATE "${PROJECT_SOURCE_DIR}/include/schc_demo_app")

add_library(${LOGGER_LIB} OBJECT "logger_helper.c")
target_include_directories(${LOGGER_LIB} PRIVATE "${PROJECT_SOURCE_DIR}/include/schc_demo_app")
target_compile_definitions(${LOGGER_LIB} PRIVATE LOG_CONFIG_FILE="${LOG_CONFIG_FILE}")
target_link_libraries(${LOGGER_LIB} PRIVATE ${ZLOG_LIB})

add_library(${CLI_LIB} OBJECT "cli_helper.c" $<TARGET_OBJECTS:${LOGGER_LIB}>)
target_include_directories(${CLI_LIB} PRIVATE "${PROJECT_SOURCE_DIR}/include/schc_demo_app")
target_link_libraries(${CLI_LIB} PRIVATE ${ZLOG_LIB})

if ("${EXT}" STREQUAL "ahoi")
    add_library(${AHOI_SERVICE} OBJECT "l2_ahoi_service.c" $<TARGET_OBJECTS:${LOGGER_LIB}>)
    target_include_directories(${AHOI_SERVICE} PRIVATE "${PROJECT_SOURCE_DIR}/include/schc_demo_app/l2")
    target_compile_definitions(${AHOI_SERVICE} PUBLIC L2_AHOI_EXT)
    target_link_libraries(${AHOI_SERVICE} PRIVATE ${AHOI_SERIAL_LIB} ${ZLOG_LIB})

    set(L2_LIB "${AHOI_SERVICE}")
endif ()

add_library(${SCHC_SERVICE} OBJECT "schc_service.c")
target_include_directories(${SCHC_SERVICE} PRIVATE
        "${PROJECT_SOURCE_DIR}/include/schc_demo_app/"
        "${PROJECT_SOURCE_DIR}/include/schc_demo_app/services")
target_link_libraries(${SCHC_SERVICE} PRIVATE ${SCHC_FULL_SDK_LIB})

add_library(${SENSOR_SERVICE} OBJECT "sensor_service.c")
target_include_directories(${SENSOR_SERVICE} PRIVATE
        "${PROJECT_SOURCE_DIR}/include/schc_demo_app/"
        "${PROJECT_SOURCE_DIR}/include/schc_demo_app/services")

add_executable(${EXEC_NAME} "main.c" $<TARGET_OBJECTS:${L2_LIB}> $<TARGET_OBJECTS:${UTILS}> $<TARGET_OBJECTS:${CLI_LIB}>
        $<TARGET_OBJECTS:${SCHC_SERVICE}> $<TARGET_OBJECTS:${SENSOR_SERVICE}> $<TARGET_OBJECTS:${LOGGER_LIB}>)
target_include_directories(${EXEC_NAME} PRIVATE "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(${EXEC_NAME} ${AHOI_SERIAL_LIB} ${ZLOG_LIB} m)