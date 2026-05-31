/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PORT_ESP32_WEBSOCKET_WEBSOCKET_CLIENT_ESP32_H_
#define PORT_ESP32_WEBSOCKET_WEBSOCKET_CLIENT_ESP32_H_

#include "src/ship/api/tls_certificate_interface.h"
#include "src/ship/api/websocket_creator_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

WebsocketCreatorObject *WebsocketClientCreatorEsp32Create(const char *uri,
                                                          const TlsCertificateObject *tls_cert,
                                                          const char *remote_ski);

#ifdef __cplusplus
}
#endif

#endif  // PORT_ESP32_WEBSOCKET_WEBSOCKET_CLIENT_ESP32_H_
