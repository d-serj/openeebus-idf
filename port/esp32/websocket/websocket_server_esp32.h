/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PORT_ESP32_WEBSOCKET_WEBSOCKET_SERVER_ESP32_H_
#define PORT_ESP32_WEBSOCKET_WEBSOCKET_SERVER_ESP32_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_http_server.h"
#include "src/ship/api/websocket_creator_interface.h"
#include "src/ship/api/websocket_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

WebsocketCreatorObject *WebsocketServerCreatorEsp32Create(httpd_handle_t server, int socket_fd);
WebsocketObject *WebsocketServerCreatorEsp32GetCreated(WebsocketCreatorObject *creator);

bool WebsocketServerEsp32Receive(WebsocketObject *websocket,
                                 uint8_t opcode,
                                 const uint8_t *data,
                                 size_t data_size,
                                 bool final_frame);
void WebsocketServerEsp32NotifyClose(WebsocketObject *websocket, int32_t close_code);
void WebsocketServerEsp32NotifyError(WebsocketObject *websocket, int32_t close_error);

#ifdef __cplusplus
}
#endif

#endif  // PORT_ESP32_WEBSOCKET_WEBSOCKET_SERVER_ESP32_H_
