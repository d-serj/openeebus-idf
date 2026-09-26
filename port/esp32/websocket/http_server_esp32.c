/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "src/ship/websocket/http_server.h"

#include <string.h>

#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_tls.h"
#include "lwip/sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "src/common/eebus_malloc.h"
#include "src/ship/api/http_server_interface.h"
#include "src/ship/api/tls_certificate_interface.h"
#include "src/ship/tls_certificate/tls_certificate.h"
#include "src/ship/websocket/websocket_creator.h"
#include "websocket_esp32_common.h"
#include "websocket_server_esp32.h"

#ifndef CONFIG_HTTPD_WS_SUPPORT
#error "OpenEEBUS SHIP requires CONFIG_HTTPD_WS_SUPPORT=y"
#endif

#ifndef CONFIG_HTTPD_WS_POST_HANDSHAKE_CB_SUPPORT
#error "OpenEEBUS SHIP requires CONFIG_HTTPD_WS_POST_HANDSHAKE_CB_SUPPORT=y"
#endif

#ifndef CONFIG_ESP_TLS_SERVER_MIN_AUTH_MODE_OPTIONAL
#error "SHIP mutual TLS requires CONFIG_ESP_TLS_SERVER_MIN_AUTH_MODE_OPTIONAL=y"
#endif

#ifndef CONFIG_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE
#error "SHIP SKI extraction requires CONFIG_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE=y"
#endif

static const char *kTag = "eebus_http_server";

typedef struct HttpServerEsp32 {
    HttpServerObject obj;
    int port;
    const TlsCertificateObject *tls_certificate;
    WebsocketServerCallbackType connection_callback;
    void *connection_context;
    httpd_handle_t server;
    esp_tls_cfg_server_t tls_config;
} HttpServerEsp32;

typedef struct ServerTlsSession {
    esp_tls_t *tls;
} ServerTlsSession;

#define HTTP_SERVER_ESP32(obj) ((HttpServerEsp32 *)(obj))

static void NoopFree(void *ctx) {
    (void)ctx;
}

static void TlsSessionFree(void *ctx) {
    ServerTlsSession *const session = ctx;
    if (session != NULL) {
        if (session->tls != NULL) {
            esp_tls_server_session_delete(session->tls);
        }
        EEBUS_FREE(session);
    }
}

static int TlsPending(httpd_handle_t server, int socket_fd) {
    ServerTlsSession *const session = httpd_sess_get_transport_ctx(server, socket_fd);
    return ((session != NULL) && (session->tls != NULL)) ? (int)esp_tls_get_bytes_avail(session->tls)
                                                         : HTTPD_SOCK_ERR_INVALID;
}

static int TlsReceive(httpd_handle_t server, int socket_fd, char *buffer, size_t buffer_size, int flags) {
    (void)flags;

    ServerTlsSession *const session = httpd_sess_get_transport_ctx(server, socket_fd);
    if ((session == NULL) || (session->tls == NULL)) {
        return HTTPD_SOCK_ERR_INVALID;
    }

    const int result = esp_tls_conn_read(session->tls, buffer, buffer_size);
    if ((result == ESP_TLS_ERR_SSL_WANT_READ) || (result == ESP_TLS_ERR_SSL_TIMEOUT)) {
        return HTTPD_SOCK_ERR_TIMEOUT;
    }

    return (result < 0) ? HTTPD_SOCK_ERR_FAIL : result;
}

static int TlsSend(httpd_handle_t server, int socket_fd, const char *buffer, size_t buffer_size, int flags) {
    (void)flags;

    ServerTlsSession *const session = httpd_sess_get_transport_ctx(server, socket_fd);
    if ((session == NULL) || (session->tls == NULL)) {
        return HTTPD_SOCK_ERR_INVALID;
    }

    const int result = esp_tls_conn_write(session->tls, buffer, buffer_size);
    return (result < 0) ? HTTPD_SOCK_ERR_FAIL : result;
}

static esp_err_t TlsOpen(httpd_handle_t server, int socket_fd) {
    HttpServerEsp32 *const http_server = httpd_get_global_transport_ctx(server);
    if (http_server == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    ServerTlsSession *const session = EEBUS_MALLOC(sizeof(*session));
    if (session == NULL) {
        return ESP_ERR_NO_MEM;
    }

    session->tls = esp_tls_init();
    if (session->tls == NULL) {
        EEBUS_FREE(session);
        return ESP_ERR_NO_MEM;
    }

    if (esp_tls_server_session_create(&http_server->tls_config, socket_fd, session->tls) != 0) {
        ESP_LOGE(kTag, "TLS server handshake failed");
        esp_tls_server_session_delete(session->tls);
        EEBUS_FREE(session);
        return ESP_FAIL;
    }

    httpd_sess_set_transport_ctx(server, socket_fd, session, TlsSessionFree);
    if ((httpd_sess_set_send_override(server, socket_fd, TlsSend) != ESP_OK)
        || (httpd_sess_set_recv_override(server, socket_fd, TlsReceive) != ESP_OK)
        || (httpd_sess_set_pending_override(server, socket_fd, TlsPending) != ESP_OK)) {
        httpd_sess_set_transport_ctx(server, socket_fd, NULL, NULL);
        return ESP_FAIL;
    }

    return ESP_OK;
}

static void SessionClosed(void *ctx) {
    WebsocketObject *const websocket = ctx;
    if (websocket != NULL) {
        WebsocketServerEsp32NotifyClose(websocket, 0);
    }
}

static void TlsClose(httpd_handle_t server, int socket_fd) {
    WebsocketObject *const websocket = httpd_sess_get_ctx(server, socket_fd);
    if (websocket != NULL) {
        WebsocketServerEsp32NotifyClose(websocket, 0);
    }
    /* The transport-context free callback deletes esp_tls and closes the socket.
     */
}

static char *PeerSki(httpd_handle_t server, int socket_fd) {
    ServerTlsSession *const session = httpd_sess_get_transport_ctx(server, socket_fd);
    if ((session == NULL) || (session->tls == NULL)) {
        return NULL;
    }

    mbedtls_ssl_context *const ssl = esp_tls_get_ssl_context(session->tls);
    const mbedtls_x509_crt *const certificate = (ssl != NULL) ? mbedtls_ssl_get_peer_cert(ssl) : NULL;
    if ((certificate == NULL) || (certificate->raw.p == NULL) || (certificate->raw.len == 0)) {
        return NULL;
    }

    return (char *)TlsCertificateCalcPublicKeySki(certificate->raw.p, certificate->raw.len);
}

static esp_err_t HandleWebsocketHandshake(httpd_req_t *request) {
    HttpServerEsp32 *const http_server = request->user_ctx;
    const int socket_fd = httpd_req_to_sockfd(request);

    char *const peer_ski = PeerSki(request->handle, socket_fd);
    if ((peer_ski == NULL) || (http_server->connection_callback == NULL)) {
        ESP_LOGE(kTag, "rejecting SHIP connection without a peer certificate");
        EEBUS_FREE(peer_ski);
        return ESP_FAIL;
    }

    WebsocketCreatorObject *const creator = WebsocketServerCreatorEsp32Create(request->handle, socket_fd);
    if (creator == NULL) {
        EEBUS_FREE(peer_ski);
        return ESP_ERR_NO_MEM;
    }

    const int callback_result = http_server->connection_callback(peer_ski, creator, http_server->connection_context);
    WebsocketObject *const websocket = WebsocketServerCreatorEsp32GetCreated(creator);
    WebsocketCreatorDelete(creator);
    EEBUS_FREE(peer_ski);

    if ((callback_result != 0) || (websocket == NULL)) {
        ESP_LOGW(kTag, "SHIP connection rejected");
        return ESP_FAIL;
    }
    httpd_sess_set_ctx(request->handle, socket_fd, websocket, SessionClosed);
    return ESP_OK;
}

static esp_err_t HandleWebsocket(httpd_req_t *request) {
    WebsocketObject *const websocket = request->sess_ctx;
    if (websocket == NULL) {
        return ESP_FAIL;
    }

    httpd_ws_frame_t frame = {0};
    esp_err_t result = httpd_ws_recv_frame(request, &frame, 0);
    if (result != ESP_OK) {
        WebsocketServerEsp32NotifyError(websocket, result);
        return result;
    }
    if (frame.len > EEBUS_WEBSOCKET_MAX_INPUT_MSG_SIZE) {
        ESP_LOGE(kTag, "WebSocket frame exceeds the input limit");
        WebsocketServerEsp32NotifyError(websocket, ESP_ERR_INVALID_SIZE);
        return ESP_ERR_INVALID_SIZE;
    }

    uint8_t *payload = NULL;
    if (frame.len > 0) {
        payload = EEBUS_MALLOC(frame.len);
        if (payload == NULL) {
            WebsocketServerEsp32NotifyError(websocket, ESP_ERR_NO_MEM);
            return ESP_ERR_NO_MEM;
        }
        frame.payload = payload;
        result = httpd_ws_recv_frame(request, &frame, frame.len);
        if (result != ESP_OK) {
            EEBUS_FREE(payload);
            WebsocketServerEsp32NotifyError(websocket, result);
            return result;
        }
    }

    if (frame.type == HTTPD_WS_TYPE_CLOSE) {
        int32_t close_code = 0;
        if (frame.len >= 2) {
            uint16_t network_code;
            memcpy(&network_code, payload, sizeof(network_code));
            close_code = ntohs(network_code);
        }
        request->sess_ctx = NULL;
        request->free_ctx = NULL;
        WebsocketServerEsp32NotifyClose(websocket, close_code);
    } else if ((frame.type == HTTPD_WS_TYPE_BINARY) || (frame.type == HTTPD_WS_TYPE_CONTINUE)) {
        if (!WebsocketServerEsp32Receive(websocket, frame.type, payload, frame.len, frame.final)) {
            result = ESP_ERR_INVALID_ARG;
            WebsocketServerEsp32NotifyError(websocket, result);
        }
    } else if (frame.type == HTTPD_WS_TYPE_PING) {
        httpd_ws_frame_t pong = {
            .final = true,
            .type = HTTPD_WS_TYPE_PONG,
            .payload = payload,
            .len = frame.len,
        };
        result = httpd_ws_send_frame(request, &pong);
    } else if (frame.type != HTTPD_WS_TYPE_PONG) {
        result = ESP_ERR_INVALID_ARG;
        WebsocketServerEsp32NotifyError(websocket, result);
    }

    EEBUS_FREE(payload);
    return result;
}

static EebusError ServerStart(HttpServerObject *self) {
    HttpServerEsp32 *const http_server = HTTP_SERVER_ESP32(self);
    if (http_server->server != NULL) {
        return kEebusErrorOk;
    }

    http_server->tls_config = (esp_tls_cfg_server_t){
        .servercert_buf = TLS_CERTIFICATE_GET_CERTIFICATE(http_server->tls_certificate),
        .servercert_bytes = TLS_CERTIFICATE_GET_CERTIFICATE_SIZE(http_server->tls_certificate),
        .serverkey_buf = TLS_CERTIFICATE_GET_PRIVATE_KEY(http_server->tls_certificate),
        .serverkey_bytes = TLS_CERTIFICATE_GET_PRIVATE_KEY_SIZE(http_server->tls_certificate),
        /* ESP-TLS only enables optional client authentication when a CA is configured.
         * SHIP authorizes peers by SKI, so verification errors are allowed here.
         */
        .cacert_buf = TLS_CERTIFICATE_GET_CERTIFICATE(http_server->tls_certificate),
        .cacert_bytes = TLS_CERTIFICATE_GET_CERTIFICATE_SIZE(http_server->tls_certificate),
        .client_cert_authmode_optional = true,
    };

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = (uint16_t)http_server->port;
    config.ctrl_port = (uint16_t)(32768 + (http_server->port % 32767));
    config.max_open_sockets = 4;
    config.stack_size = 8192;
    config.open_fn = TlsOpen;
    config.close_fn = TlsClose;
    config.global_transport_ctx = http_server;
    config.global_transport_ctx_free_fn = NoopFree;

    esp_err_t result = httpd_start(&http_server->server, &config);
    if (result != ESP_OK) {
        ESP_LOGE(kTag, "HTTP server start failed: %s", esp_err_to_name(result));
        return kEebusErrorOther;
    }

    const httpd_uri_t uri = {
        .uri = "/ship/",
        .method = HTTP_GET,
        .handler = HandleWebsocket,
        .user_ctx = http_server,
        .is_websocket = true,
        .handle_ws_control_frames = true,
        .supported_subprotocol = "ship",
        .ws_post_handshake_cb = HandleWebsocketHandshake,
    };

    result = httpd_register_uri_handler(http_server->server, &uri);
    if (result != ESP_OK) {
        httpd_stop(http_server->server);
        http_server->server = NULL;
        ESP_LOGE(kTag, "SHIP URI registration failed: %s", esp_err_to_name(result));
        return kEebusErrorOther;
    }

    return kEebusErrorOk;
}

static void ServerStop(HttpServerObject *self) {
    HttpServerEsp32 *const http_server = HTTP_SERVER_ESP32(self);
    if (http_server->server != NULL) {
        httpd_stop(http_server->server);
        http_server->server = NULL;
    }
}

static void ServerDestruct(HttpServerObject *self) {
    ServerStop(self);
}

static const HttpServerInterface kServerMethods = {
    .destruct = ServerDestruct,
    .start = ServerStart,
    .stop = ServerStop,
};

HttpServerObject *HttpServerCreate(int port,
                                   const TlsCertificateObject *tls_cert,
                                   WebsocketServerCallbackType connection_callback,
                                   void *connection_context) {
    if ((port <= 0) || (port > UINT16_MAX) || (tls_cert == NULL)) {
        return NULL;
    }

    HttpServerEsp32 *const http_server = EEBUS_MALLOC(sizeof(*http_server));
    if (http_server == NULL) {
        return NULL;
    }

    memset(http_server, 0, sizeof(*http_server));

    HTTP_SERVER_INTERFACE(http_server) = &kServerMethods;
    http_server->port = port;
    http_server->tls_certificate = tls_cert;
    http_server->connection_callback = connection_callback;
    http_server->connection_context = connection_context;

    return HTTP_SERVER_OBJECT(http_server);
}
