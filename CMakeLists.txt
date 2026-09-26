set(EEBUS_DIR ${CMAKE_CURRENT_LIST_DIR}/openeebus)

set(FREERTOS ON)
include(${EEBUS_DIR}/sources.cmake)

# OpenEEBUS' default transport is libwebsockets. Keep the upstream submodule
# untouched and replace only those sources at the ESP-IDF component boundary.
list(REMOVE_ITEM SOURCES
    src/common/debug.c
    src/ship/websocket/websocket.c
    src/ship/websocket/websocket_client_creator.c
    src/ship/websocket/websocket_server_creator.c
    src/ship/websocket/websocket_client.c
    src/ship/websocket/websocket_server.c
    src/ship/websocket/http_server.c
    src/ship/websocket/websocket_debug.c
)

list(APPEND SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/port/esp32/oe_debug_esp32.c
    ${CMAKE_CURRENT_LIST_DIR}/port/esp32/websocket/websocket_esp32_common.c
    ${CMAKE_CURRENT_LIST_DIR}/port/esp32/websocket/websocket_client_creator_esp32.c
    ${CMAKE_CURRENT_LIST_DIR}/port/esp32/websocket/websocket_client_esp32.c
    ${CMAKE_CURRENT_LIST_DIR}/port/esp32/websocket/websocket_server_esp32.c
    ${CMAKE_CURRENT_LIST_DIR}/port/esp32/websocket/http_server_esp32.c
)

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
    REQUIRES
        freertos
        espressif__cjson
        mbedtls
        esp_wifi
        nvs_flash
        driver
        spi_flash
        esp_http_server
        esp-tls
        tcp_transport
        lwip
        espressif__mdns
        espressif__esp_websocket_client
)

target_compile_definitions(${COMPONENT_LIB} PUBLIC __freertos__)
