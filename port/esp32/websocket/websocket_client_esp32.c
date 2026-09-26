/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "websocket_client_esp32.h"

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/select.h>

#include "esp_log.h"
#include "esp_tls.h"
#include "esp_transport.h"
#include "esp_transport_ws.h"
#include "esp_websocket_client.h"
#include "freertos/event_groups.h"
#include "lwip/sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "src/common/eebus_malloc.h"
#include "src/ship/api/tls_certificate_interface.h"
#include "src/ship/api/websocket_interface.h"
#include "src/ship/tls_certificate/tls_certificate.h"
#include "websocket_esp32_common.h"

#ifndef CONFIG_ESP_TLS_INSECURE
#error "SHIP SKI pinning requires CONFIG_ESP_TLS_INSECURE=y"
#endif

#ifndef CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY
#error "SHIP SKI pinning requires CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY=y"
#endif

#ifndef CONFIG_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE
#error "SHIP SKI pinning requires CONFIG_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE=y"
#endif

static const char *kTag = "eebus_ws_client";

enum {
    kConnectedBit = BIT0,
    kTerminalBit = BIT1,
};

typedef struct Esp32PinnedTlsTransport {
    esp_tls_t *tls;
    int socket_fd;
    uint8_t *certificate;
    size_t certificate_size;
    uint8_t *private_key;
    size_t private_key_size;
    char *remote_ski;
} Esp32PinnedTlsTransport;

typedef struct WebsocketClientEsp32 {
    WebsocketObject obj;
    Esp32WebsocketState state;
    esp_websocket_client_handle_t client;
    esp_transport_handle_t websocket_transport;
    esp_transport_handle_t tls_transport;
    SemaphoreHandle_t write_mutex;
    EventGroupHandle_t events;
} WebsocketClientEsp32;

typedef struct WebsocketClientCreatorEsp32 {
    WebsocketCreatorObject obj;
    char *uri;
    uint8_t *certificate;
    size_t certificate_size;
    uint8_t *private_key;
    size_t private_key_size;
    char *remote_ski;
} WebsocketClientCreatorEsp32;

#define WS_CLIENT(obj) ((WebsocketClientEsp32 *)(obj))
#define WS_CLIENT_CREATOR(obj) ((WebsocketClientCreatorEsp32 *)(obj))

static void ClientDestruct(WebsocketObject *self);
static int32_t ClientWrite(WebsocketObject *self, const uint8_t *msg, size_t msg_size);
static void ClientClose(WebsocketObject *self, int32_t close_code, const char *reason);
static bool ClientIsClosed(const WebsocketObject *self);
static int32_t ClientGetCloseError(const WebsocketObject *self);
static void ClientScheduleWrite(WebsocketObject *self);

static const WebsocketInterface kClientMethods = {
    .destruct = ClientDestruct,
    .write = ClientWrite,
    .close = ClientClose,
    .is_closed = ClientIsClosed,
    .get_close_error = ClientGetCloseError,
    .schedule_write = ClientScheduleWrite,
};

static uint8_t *CopyBytes(const void *source, size_t size) {
    if ((source == NULL) || (size == 0)) {
        return NULL;
    }
    uint8_t *const copy = EEBUS_MALLOC(size);
    if (copy != NULL) {
        memcpy(copy, source, size);
    }
    return copy;
}

static char *CopyString(const char *source) {
    if (source == NULL) {
        return NULL;
    }
    const size_t size = strlen(source) + 1;
    char *const copy = EEBUS_MALLOC(size);
    if (copy != NULL) {
        memcpy(copy, source, size);
    }
    return copy;
}

static int PollSocket(int socket_fd, bool write, int timeout_ms) {
    if (socket_fd < 0) {
        return -1;
    }

    fd_set read_set;
    fd_set write_set;
    fd_set error_set;
    FD_ZERO(&read_set);
    FD_ZERO(&write_set);
    FD_ZERO(&error_set);
    FD_SET(socket_fd, write ? &write_set : &read_set);
    FD_SET(socket_fd, &error_set);

    struct timeval timeout;
    struct timeval *timeout_ptr = NULL;
    if (timeout_ms >= 0) {
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;
        timeout_ptr = &timeout;
    }

    const int result
        = select(socket_fd + 1, write ? NULL : &read_set, write ? &write_set : NULL, &error_set, timeout_ptr);
    if ((result > 0) && FD_ISSET(socket_fd, &error_set)) {
        return -1;
    }

    return result;
}

static int PinnedTlsConnect(esp_transport_handle_t transport, const char *host, int port, int timeout_ms) {
    Esp32PinnedTlsTransport *const context = esp_transport_get_context_data(transport);
    if ((context == NULL) || (host == NULL) || (context->remote_ski == NULL)) {
        return -1;
    }

    esp_tls_cfg_t config = {
        .clientcert_buf = context->certificate,
        .clientcert_bytes = context->certificate_size,
        .clientkey_buf = context->private_key,
        .clientkey_bytes = context->private_key_size,
        .timeout_ms = timeout_ms,
        .skip_common_name = true,
    };

    context->tls = esp_tls_init();
    if (context->tls == NULL) {
        return -1;
    }
    if (esp_tls_conn_new_sync(host, strlen(host), port, &config, context->tls) != 1) {
        ESP_LOGE(kTag, "TLS connection failed");
        esp_tls_conn_destroy(context->tls);
        context->tls = NULL;
        return -1;
    }
    if (esp_tls_get_conn_sockfd(context->tls, &context->socket_fd) != ESP_OK) {
        ESP_LOGE(kTag, "could not obtain TLS socket");
        esp_tls_conn_destroy(context->tls);
        context->tls = NULL;
        context->socket_fd = -1;
        return -1;
    }

    mbedtls_ssl_context *const ssl = esp_tls_get_ssl_context(context->tls);
    const mbedtls_x509_crt *const peer_certificate = (ssl != NULL) ? mbedtls_ssl_get_peer_cert(ssl) : NULL;
    if ((peer_certificate == NULL) || (peer_certificate->raw.p == NULL) || (peer_certificate->raw.len == 0)) {
        ESP_LOGE(kTag, "server did not provide a certificate");
        esp_tls_conn_destroy(context->tls);
        context->tls = NULL;
        context->socket_fd = -1;
        return -1;
    }

    const char *const actual_ski = TlsCertificateCalcPublicKeySki(peer_certificate->raw.p, peer_certificate->raw.len);
    const bool ski_matches = (actual_ski != NULL) && (strcmp(actual_ski, context->remote_ski) == 0);
    if (!ski_matches) {
        ESP_LOGE(kTag, "server certificate SKI does not match the trusted SKI");
    }
    EEBUS_FREE((void *)actual_ski);
    if (!ski_matches) {
        esp_tls_conn_destroy(context->tls);
        context->tls = NULL;
        context->socket_fd = -1;
        return -1;
    }

    return 0;
}

static int PinnedTlsPollRead(esp_transport_handle_t transport, int timeout_ms) {
    Esp32PinnedTlsTransport *const context = esp_transport_get_context_data(transport);
    if ((context == NULL) || (context->tls == NULL)) {
        return -1;
    }

    const ssize_t available = esp_tls_get_bytes_avail(context->tls);
    return (available > 0) ? (int)available : PollSocket(context->socket_fd, false, timeout_ms);
}

static int PinnedTlsPollWrite(esp_transport_handle_t transport, int timeout_ms) {
    Esp32PinnedTlsTransport *const context = esp_transport_get_context_data(transport);
    return (context != NULL) ? PollSocket(context->socket_fd, true, timeout_ms) : -1;
}

static int PinnedTlsRead(esp_transport_handle_t transport, char *buffer, int length, int timeout_ms) {
    Esp32PinnedTlsTransport *const context = esp_transport_get_context_data(transport);
    const int poll_result = PinnedTlsPollRead(transport, timeout_ms);
    if ((context == NULL) || (context->tls == NULL) || (poll_result < 0)) {
        return ERR_TCP_TRANSPORT_CONNECTION_FAILED;
    }

    if (poll_result == 0) {
        return ERR_TCP_TRANSPORT_CONNECTION_TIMEOUT;
    }

    int result = esp_tls_conn_read(context->tls, (unsigned char *)buffer, length);
    if ((result == ESP_TLS_ERR_SSL_WANT_READ) || (result == ESP_TLS_ERR_SSL_TIMEOUT)) {
        return ERR_TCP_TRANSPORT_CONNECTION_TIMEOUT;
    }

    if (result == 0) {
        return ERR_TCP_TRANSPORT_CONNECTION_CLOSED_BY_FIN;
    }

    return result;
}

static int PinnedTlsWrite(esp_transport_handle_t transport, const char *buffer, int length, int timeout_ms) {
    Esp32PinnedTlsTransport *const context = esp_transport_get_context_data(transport);
    const int poll_result = PinnedTlsPollWrite(transport, timeout_ms);
    if ((context == NULL) || (context->tls == NULL) || (poll_result <= 0)) {
        return poll_result;
    }

    return esp_tls_conn_write(context->tls, (const unsigned char *)buffer, length);
}

static int PinnedTlsClose(esp_transport_handle_t transport) {
    Esp32PinnedTlsTransport *const context = esp_transport_get_context_data(transport);
    if ((context == NULL) || (context->tls == NULL)) {
        return 0;
    }

    const int result = esp_tls_conn_destroy(context->tls);
    context->tls = NULL;
    context->socket_fd = -1;

    return result;
}

static int PinnedTlsDestroy(esp_transport_handle_t transport) {
    Esp32PinnedTlsTransport *const context = esp_transport_get_context_data(transport);
    if (context == NULL) {
        return 0;
    }

    PinnedTlsClose(transport);
    EEBUS_FREE(context->certificate);
    EEBUS_FREE(context->private_key);
    EEBUS_FREE(context->remote_ski);
    EEBUS_FREE(context);
    esp_transport_set_context_data(transport, NULL);

    return 0;
}

static esp_transport_handle_t CreatePinnedTlsTransport(const WebsocketClientCreatorEsp32 *creator) {
    esp_transport_handle_t transport = esp_transport_init();
    if (transport == NULL) {
        return NULL;
    }

    Esp32PinnedTlsTransport *const context = EEBUS_MALLOC(sizeof(*context));
    if (context == NULL) {
        esp_transport_destroy(transport);
        return NULL;
    }

    memset(context, 0, sizeof(*context));
    context->socket_fd = -1;
    context->certificate = CopyBytes(creator->certificate, creator->certificate_size);
    context->certificate_size = creator->certificate_size;
    context->private_key = CopyBytes(creator->private_key, creator->private_key_size);
    context->private_key_size = creator->private_key_size;
    context->remote_ski = CopyString(creator->remote_ski);

    if ((context->certificate == NULL) || (context->private_key == NULL) || (context->remote_ski == NULL)) {
        EEBUS_FREE(context->certificate);
        EEBUS_FREE(context->private_key);
        EEBUS_FREE(context->remote_ski);
        EEBUS_FREE(context);
        esp_transport_destroy(transport);
        return NULL;
    }

    esp_transport_set_context_data(transport, context);
    esp_transport_set_func(transport,
                           PinnedTlsConnect,
                           PinnedTlsRead,
                           PinnedTlsWrite,
                           PinnedTlsClose,
                           PinnedTlsPollRead,
                           PinnedTlsPollWrite,
                           PinnedTlsDestroy);
    esp_transport_set_default_port(transport, 443);
    return transport;
}

static char *UriPath(const char *uri) {
    const char *authority = strstr(uri, "://");
    authority = (authority != NULL) ? authority + 3 : uri;
    const char *path = strchr(authority, '/');
    return CopyString((path != NULL) ? path : "/");
}

static void ClientEventHandler(void *arg, esp_event_base_t base, int32_t event_id, void *event_data) {
    (void)base;
    WebsocketClientEsp32 *const websocket = arg;
    esp_websocket_event_data_t *const data = event_data;

    switch (event_id) {
        case WEBSOCKET_EVENT_CONNECTED:
            xEventGroupSetBits(websocket->events, kConnectedBit);
            break;

        case WEBSOCKET_EVENT_DATA:
            if ((data == NULL) || (data->data_len < 0) || (data->payload_len < 0) || (data->payload_offset < 0)) {
                ESP_LOGE(kTag, "invalid WebSocket event lengths");
                xEventGroupSetBits(websocket->events, kTerminalBit);
                Esp32WebsocketStateNotifyTerminal(&websocket->state, kWebsocketCallbackTypeError, -1);
                break;
            }
            if (data->op_code == WS_TRANSPORT_OPCODES_CLOSE) {
                int32_t close_code = 0;
                if ((data->data_ptr != NULL) && (data->data_len >= 2)) {
                    uint16_t network_code;
                    memcpy(&network_code, data->data_ptr, sizeof(network_code));
                    close_code = ntohs(network_code);
                }
                xEventGroupSetBits(websocket->events, kTerminalBit);
                Esp32WebsocketStateNotifyTerminal(&websocket->state, kWebsocketCallbackTypeClose, close_code);
            } else if ((data->op_code == WS_TRANSPORT_OPCODES_PING)
                       || (data->op_code == WS_TRANSPORT_OPCODES_PONG)) {
                // esp_websocket_client handles PING and PONG after dispatching their data events.
                break;
            } else if (!Esp32WebsocketStateReceive(&websocket->state,
                                                   data->op_code,
                                                   (const uint8_t *)data->data_ptr,
                                                   (size_t)data->data_len,
                                                   (size_t)data->payload_len,
                                                   (size_t)data->payload_offset,
                                                   data->fin)) {
                ESP_LOGE(kTag, "invalid or over-sized WebSocket message");
                xEventGroupSetBits(websocket->events, kTerminalBit);
                Esp32WebsocketStateNotifyTerminal(&websocket->state, kWebsocketCallbackTypeError, -1);
            }
            break;

        case WEBSOCKET_EVENT_ERROR:
            xEventGroupSetBits(websocket->events, kTerminalBit);
            Esp32WebsocketStateNotifyTerminal(&websocket->state, kWebsocketCallbackTypeError, -1);
            break;

        case WEBSOCKET_EVENT_CLOSED:
        case WEBSOCKET_EVENT_DISCONNECTED:
            xEventGroupSetBits(websocket->events, kTerminalBit);
            Esp32WebsocketStateNotifyTerminal(&websocket->state, kWebsocketCallbackTypeClose, 0);
            break;

        default:
            break;
    }
}

static void ClientDestruct(WebsocketObject *self) {
    WebsocketClientEsp32 *const websocket = WS_CLIENT(self);
    if (websocket->client != NULL) {
        esp_websocket_client_destroy(websocket->client);
        websocket->client = NULL;
    }
    if (websocket->websocket_transport != NULL) {
        esp_transport_destroy(websocket->websocket_transport);
        websocket->websocket_transport = NULL;
    }
    if (websocket->tls_transport != NULL) {
        esp_transport_destroy(websocket->tls_transport);
        websocket->tls_transport = NULL;
    }
    if (websocket->write_mutex != NULL) {
        vSemaphoreDelete(websocket->write_mutex);
        websocket->write_mutex = NULL;
    }
    if (websocket->events != NULL) {
        vEventGroupDelete(websocket->events);
        websocket->events = NULL;
    }
    Esp32WebsocketStateDeinit(&websocket->state);
}

static int32_t ClientWrite(WebsocketObject *self, const uint8_t *msg, size_t msg_size) {
    WebsocketClientEsp32 *const websocket = WS_CLIENT(self);
    if ((msg == NULL) || (msg_size > INT_MAX) || Esp32WebsocketStateIsClosed(&websocket->state)) {
        return 0;
    }

    const EventBits_t bits
        = xEventGroupWaitBits(websocket->events, kConnectedBit | kTerminalBit, pdFALSE, pdFALSE, pdMS_TO_TICKS(10000));
    if (((bits & kConnectedBit) == 0) || ((bits & kTerminalBit) != 0)) {
        return 0;
    }

    xSemaphoreTake(websocket->write_mutex, portMAX_DELAY);
    const int result
        = esp_websocket_client_send_bin(websocket->client, (const char *)msg, (int)msg_size, pdMS_TO_TICKS(10000));
    xSemaphoreGive(websocket->write_mutex);

    return (result == (int)msg_size) ? (int32_t)msg_size : 0;
}

static void ClientClose(WebsocketObject *self, int32_t close_code, const char *reason) {
    WebsocketClientEsp32 *const websocket = WS_CLIENT(self);
    Esp32WebsocketStateMarkClosed(&websocket->state, close_code);
    xEventGroupSetBits(websocket->events, kTerminalBit);

    if ((websocket->client == NULL) || !esp_websocket_client_is_connected(websocket->client)) {
        return;
    }
    const char *const close_reason = (reason != NULL) ? reason : "";
    const size_t reason_size = strlen(close_reason);
    const int safe_reason_size = (int)((reason_size > 123) ? 123 : reason_size);
    esp_websocket_client_close_with_code(websocket->client,
                                         (int)close_code,
                                         close_reason,
                                         safe_reason_size,
                                         pdMS_TO_TICKS(2000));
}

static bool ClientIsClosed(const WebsocketObject *self) {
    return Esp32WebsocketStateIsClosed(&WS_CLIENT(self)->state);
}

static int32_t ClientGetCloseError(const WebsocketObject *self) {
    return Esp32WebsocketStateGetCloseError(&WS_CLIENT(self)->state);
}

static void ClientScheduleWrite(WebsocketObject *self) {
    (void)self;
}

static void CreatorDestruct(WebsocketCreatorObject *self) {
    WebsocketClientCreatorEsp32 *const creator = WS_CLIENT_CREATOR(self);
    EEBUS_FREE(creator->uri);
    EEBUS_FREE(creator->certificate);
    EEBUS_FREE(creator->private_key);
    EEBUS_FREE(creator->remote_ski);
    creator->uri = NULL;
    creator->certificate = NULL;
    creator->private_key = NULL;
    creator->remote_ski = NULL;
}

static WebsocketObject *CreatorCreateWebsocket(WebsocketCreatorObject *self, WebsocketCallback callback, void *ctx) {
    WebsocketClientCreatorEsp32 *const creator = WS_CLIENT_CREATOR(self);
    WebsocketClientEsp32 *const websocket = EEBUS_MALLOC(sizeof(*websocket));
    if (websocket == NULL) {
        return NULL;
    }

    memset(websocket, 0, sizeof(*websocket));
    WEBSOCKET_INTERFACE(websocket) = &kClientMethods;

    if (!Esp32WebsocketStateInit(&websocket->state, callback, ctx)) {
        EEBUS_FREE(websocket);
        return NULL;
    }
    websocket->write_mutex = xSemaphoreCreateMutex();
    websocket->events = xEventGroupCreate();
    websocket->tls_transport = CreatePinnedTlsTransport(creator);
    if (websocket->tls_transport != NULL) {
        websocket->websocket_transport = esp_transport_ws_init(websocket->tls_transport);
    }

    char *const path = UriPath(creator->uri);
    if ((websocket->write_mutex == NULL) || (websocket->events == NULL) || (websocket->tls_transport == NULL)
        || (websocket->websocket_transport == NULL) || (path == NULL)) {
        EEBUS_FREE(path);
        ClientDestruct(WEBSOCKET_OBJECT(websocket));
        EEBUS_FREE(websocket);
        return NULL;
    }

    esp_transport_set_default_port(websocket->websocket_transport, 443);
    const esp_transport_ws_config_t transport_config = {
        .ws_path = path,
        .sub_protocol = "ship",
        .propagate_control_frames = true,
    };
    const esp_err_t transport_result = esp_transport_ws_set_config(websocket->websocket_transport, &transport_config);
    EEBUS_FREE(path);
    if (transport_result != ESP_OK) {
        ClientDestruct(WEBSOCKET_OBJECT(websocket));
        EEBUS_FREE(websocket);
        return NULL;
    }

    const esp_websocket_client_config_t config = {
        .uri = creator->uri,
        .disable_auto_reconnect = true,
        .subprotocol = "ship",
        .network_timeout_ms = 10000,
        .task_stack = 8192,
        .buffer_size = 4096,
        .transport = WEBSOCKET_TRANSPORT_OVER_SSL,
        .ext_transport = websocket->websocket_transport,
    };
    websocket->client = esp_websocket_client_init(&config);
    if ((websocket->client == NULL)
        || (esp_websocket_register_events(websocket->client, WEBSOCKET_EVENT_ANY, ClientEventHandler, websocket)
            != ESP_OK)
        || (esp_websocket_client_start(websocket->client) != ESP_OK)) {
        ESP_LOGE(kTag, "could not start WebSocket client");
        ClientDestruct(WEBSOCKET_OBJECT(websocket));
        EEBUS_FREE(websocket);
        return NULL;
    }

    return WEBSOCKET_OBJECT(websocket);
}

static const WebsocketCreatorInterface kCreatorMethods = {
    .destruct = CreatorDestruct,
    .create_websocket = CreatorCreateWebsocket,
};

WebsocketCreatorObject *WebsocketClientCreatorEsp32Create(const char *uri,
                                                          const TlsCertificateObject *tls_cert,
                                                          const char *remote_ski) {
    if ((uri == NULL) || (tls_cert == NULL) || (remote_ski == NULL) || (remote_ski[0] == '\0')) {
        return NULL;
    }

    WebsocketClientCreatorEsp32 *const creator = EEBUS_MALLOC(sizeof(*creator));
    if (creator == NULL) {
        return NULL;
    }
    memset(creator, 0, sizeof(*creator));
    WEBSOCKET_CREATOR_INTERFACE(creator) = &kCreatorMethods;

    creator->uri = CopyString(uri);
    creator->certificate_size = TLS_CERTIFICATE_GET_CERTIFICATE_SIZE(tls_cert);
    creator->certificate = CopyBytes(TLS_CERTIFICATE_GET_CERTIFICATE(tls_cert), creator->certificate_size);
    creator->private_key_size = TLS_CERTIFICATE_GET_PRIVATE_KEY_SIZE(tls_cert);
    creator->private_key = CopyBytes(TLS_CERTIFICATE_GET_PRIVATE_KEY(tls_cert), creator->private_key_size);
    creator->remote_ski = CopyString(remote_ski);

    if ((creator->uri == NULL) || (creator->certificate == NULL) || (creator->private_key == NULL)
        || (creator->remote_ski == NULL)) {
        CreatorDestruct(WEBSOCKET_CREATOR_OBJECT(creator));
        EEBUS_FREE(creator);
        return NULL;
    }

    return WEBSOCKET_CREATOR_OBJECT(creator);
}
