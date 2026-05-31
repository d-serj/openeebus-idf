set(EEBUS_DIR ${CMAKE_CURRENT_LIST_DIR}/openeebus)

set(FREERTOS ON)
include(${EEBUS_DIR}/sources.cmake)

foreach(src ${SOURCES})
    if(IS_ABSOLUTE "${src}")
        list(APPEND EEBUS_SRCS "${src}")
    else()
        list(APPEND EEBUS_SRCS "${EEBUS_DIR}/${src}")
    endif()
endforeach()

idf_component_register(
    SRCS ${EEBUS_SRCS}
    INCLUDE_DIRS "${EEBUS_DIR}"
    REQUIRES freertos json mbedtls esp_wifi nvs_flash driver spi_flash espressif__mdns espressif__libwebsockets
)

target_compile_definitions(${COMPONENT_LIB} PUBLIC __freertos__)
