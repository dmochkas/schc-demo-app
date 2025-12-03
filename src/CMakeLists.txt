
set(EXEC_NAME "schc-demo-app")
set(AHOI_SERVICE "ahoi-service-lib")

add_library(${AHOI_SERVICE} OBJECT "l2_ahoi_service.c")

target_include_directories(${AHOI_SERVICE} PRIVATE "${PROJECT_SOURCE_DIR}/include/schc_demo_app/services")

add_executable(${EXEC_NAME} "main.c")
target_link_libraries(${EXEC_NAME} ${AHOI_SERIAL_LIB} ${AHOI_SERVICE})