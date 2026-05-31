/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "websocket_server_esp32.h"

#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "lwip/sockets.h"
#include "src/common/eebus_malloc.h"
#include "src/ship/api/websocket_interface.h"
#include "websocket_esp32_common.h"

static const char *kTag = "eebus_ws_server";

typedef struct WebsocketServerEsp32 {
    WebsocketObject obj;
    Esp32WebsocketState state;
    httpd_handle_t server;
    int socket_fd;
    SemaphoreHandle_t write_mutex;
} WebsocketServerEsp32;

typedef struct WebsocketServerCreatorEsp32 {
    WebsocketCreatorObject obj;
    httpd_handle_t server;
    int socket_fd;
    WebsocketObject *created_websocket;
} WebsocketServerCreatorEsp32;

#define WS_SERVER(obj) ((WebsocketServerEsp32 *)(obj))
#define WS_SERVER_CREATOR(obj) ((WebsocketServerCreatorEsp32 *)(obj))

static void NoopFree(void *ctx) {
    (void)ctx;
}

static void ServerDestruct(WebsocketObject *self) {
    WebsocketServerEsp32 *const websocket = WS_SERVER(self);

    if ((websocket->server != NULL) && (websocket->socket_fd >= 0)
        && (httpd_sess_get_ctx(websocket->server, websocket->socket_fd) == websocket)) {
        /* Replacing a session context normally invokes its free callback. Replace
         * that callback first so this object remains owned by ShipConnection. */
        httpd_sess_set_ctx(websocket->server, websocket->socket_fd, websocket, NoopFree);
        httpd_sess_set_ctx(websocket->server, websocket->socket_fd, NULL, NULL);
    }

    if (!Esp32WebsocketStateIsClosed(&websocket->state) && (websocket->server != NULL) && (websocket->socket_fd >= 0)) {
        httpd_ws_frame_t close_frame = {
            .final = true,
            .type = HTTPD_WS_TYPE_CLOSE,
            .payload = NULL,
            .len = 0,
        };
        httpd_ws_send_frame_async(websocket->server, websocket->socket_fd, &close_frame);
    }

    Esp32WebsocketStateMarkClosed(&websocket->state, 0);
    websocket->socket_fd = -1;
    if (websocket->write_mutex != NULL) {
        vSemaphoreDelete(websocket->write_mutex);
        websocket->write_mutex = NULL;
    }
    Esp32WebsocketStateDeinit(&websocket->state);
}

static int32_t ServerWrite(WebsocketObject *self, const uint8_t *msg, size_t msg_size) {
    WebsocketServerEsp32 *const websocket = WS_SERVER(self);
    if ((msg == NULL) || (msg_size > INT32_MAX) || Esp32WebsocketStateIsClosed(&websocket->state)
        || (websocket->server == NULL) || (websocket->socket_fd < 0)) {
        return 0;
    }

    httpd_ws_frame_t frame = {
        .final = true,
        .fragmented = false,
        .type = HTTPD_WS_TYPE_BINARY,
        .payload = (uint8_t *)msg,
        .len = msg_size,
    };
    xSemaphoreTake(websocket->write_mutex, portMAX_DELAY);
    const esp_err_t result = httpd_ws_send_frame_async(websocket->server, websocket->socket_fd, &frame);
    xSemaphoreGive(websocket->write_mutex);
    if (result != ESP_OK) {
        ESP_LOGE(kTag, "sending WebSocket frame failed: %s", esp_err_to_name(result));
        return 0;
    }
    return (int32_t)msg_size;
}

static void ServerClose(WebsocketObject *self, int32_t close_code, const char *reason) {
    WebsocketServerEsp32 *const websocket = WS_SERVER(self);
    if (Esp32WebsocketStateIsClosed(&websocket->state)) {
        return;
    }
    Esp32WebsocketStateMarkClosed(&websocket->state, close_code);

    if ((websocket->server == NULL) || (websocket->socket_fd < 0)) {
        return;
    }

    const char *const close_reason = (reason != NULL) ? reason : "";
    const size_t reason_size = strlen(close_reason);
    const size_t safe_reason_size = (reason_size > 123) ? 123 : reason_size;
    uint8_t payload[125];
    const uint16_t network_code = htons((uint16_t)close_code);
    memcpy(payload, &network_code, sizeof(network_code));
    memcpy(payload + sizeof(network_code), close_reason, safe_reason_size);
    httpd_ws_frame_t frame = {
        .final = true,
        .type = HTTPD_WS_TYPE_CLOSE,
        .payload = payload,
        .len = sizeof(network_code) + safe_reason_size,
    };

    xSemaphoreTake(websocket->write_mutex, portMAX_DELAY);
    httpd_ws_send_frame_async(websocket->server, websocket->socket_fd, &frame);
    xSemaphoreGive(websocket->write_mutex);
}

static bool ServerIsClosed(const WebsocketObject *self) {
    return Esp32WebsocketStateIsClosed(&WS_SERVER(self)->state);
}

static int32_t ServerGetCloseError(const WebsocketObject *self) {
    return Esp32WebsocketStateGetCloseError(&WS_SERVER(self)->state);
}

static void ServerScheduleWrite(WebsocketObject *self) {
    (void)self;
}

static const WebsocketInterface kServerMethods = {
    .destruct = ServerDestruct,
    .write = ServerWrite,
    .close = ServerClose,
    .is_closed = ServerIsClosed,
    .get_close_error = ServerGetCloseError,
    .schedule_write = ServerScheduleWrite,
};

bool WebsocketServerEsp32Receive(WebsocketObject *self,
                                 uint8_t opcode,
                                 const uint8_t *data,
                                 size_t data_size,
                                 bool final_frame) {
    return Esp32WebsocketStateReceive(&WS_SERVER(self)->state, opcode, data, data_size, data_size, 0, final_frame);
}

void WebsocketServerEsp32NotifyClose(WebsocketObject *self, int32_t close_code) {
    WebsocketServerEsp32 *const websocket = WS_SERVER(self);
    websocket->socket_fd = -1;
    Esp32WebsocketStateNotifyTerminal(&websocket->state, kWebsocketCallbackTypeClose, close_code);
}

void WebsocketServerEsp32NotifyError(WebsocketObject *self, int32_t close_error) {
    WebsocketServerEsp32 *const websocket = WS_SERVER(self);
    websocket->socket_fd = -1;
    Esp32WebsocketStateNotifyTerminal(&websocket->state, kWebsocketCallbackTypeError, close_error);
}

static void CreatorDestruct(WebsocketCreatorObject *self) {
    (void)self;
}

static WebsocketObject *CreatorCreateWebsocket(WebsocketCreatorObject *self, WebsocketCallback callback, void *ctx) {
    WebsocketServerCreatorEsp32 *const creator = WS_SERVER_CREATOR(self);
    if (creator->created_websocket != NULL) {
        return NULL;
    }

    WebsocketServerEsp32 *const websocket = EEBUS_MALLOC(sizeof(*websocket));
    if (websocket == NULL) {
        return NULL;
    }
    memset(websocket, 0, sizeof(*websocket));
    WEBSOCKET_INTERFACE(websocket) = &kServerMethods;
    websocket->server = creator->server;
    websocket->socket_fd = creator->socket_fd;
    websocket->write_mutex = xSemaphoreCreateMutex();
    if ((websocket->write_mutex == NULL) || !Esp32WebsocketStateInit(&websocket->state, callback, ctx)) {
        if (websocket->write_mutex != NULL) {
            vSemaphoreDelete(websocket->write_mutex);
        }
        EEBUS_FREE(websocket);
        return NULL;
    }

    creator->created_websocket = WEBSOCKET_OBJECT(websocket);
    return creator->created_websocket;
}

static const WebsocketCreatorInterface kCreatorMethods = {
    .destruct = CreatorDestruct,
    .create_websocket = CreatorCreateWebsocket,
};

WebsocketCreatorObject *WebsocketServerCreatorEsp32Create(httpd_handle_t server, int socket_fd) {
    WebsocketServerCreatorEsp32 *const creator = EEBUS_MALLOC(sizeof(*creator));
    if (creator == NULL) {
        return NULL;
    }
    memset(creator, 0, sizeof(*creator));
    WEBSOCKET_CREATOR_INTERFACE(creator) = &kCreatorMethods;
    creator->server = server;
    creator->socket_fd = socket_fd;
    return WEBSOCKET_CREATOR_OBJECT(creator);
}

WebsocketObject *WebsocketServerCreatorEsp32GetCreated(WebsocketCreatorObject *creator) {
    return WS_SERVER_CREATOR(creator)->created_websocket;
}
