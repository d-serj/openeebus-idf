/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "src/ship/websocket/websocket_client_creator.h"

#include "websocket_client_esp32.h"

WebsocketCreatorObject *WebsocketClientCreatorCreate(const char *uri,
                                                     const TlsCertificateObject *tls_cert,
                                                     const char *remote_ski) {
    return WebsocketClientCreatorEsp32Create(uri, tls_cert, remote_ski);
}
