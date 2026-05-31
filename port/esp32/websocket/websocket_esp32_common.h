/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PORT_ESP32_WEBSOCKET_WEBSOCKET_ESP32_COMMON_H_
#define PORT_ESP32_WEBSOCKET_WEBSOCKET_ESP32_COMMON_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "src/ship/api/websocket_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef EEBUS_WEBSOCKET_MAX_INPUT_MSG_SIZE
#define EEBUS_WEBSOCKET_MAX_INPUT_MSG_SIZE (64 * 1024)
#endif

enum {
    kEsp32WebsocketOpcodeContinuation = 0x0,
    kEsp32WebsocketOpcodeBinary = 0x2,
};

typedef struct Esp32WebsocketState {
    WebsocketCallback callback;
    void *callback_ctx;
    SemaphoreHandle_t mutex;
    bool closed;
    bool terminal_notified;
    int32_t close_error;

    uint8_t *rx_buffer;
    size_t rx_size;
    size_t frame_size;
    size_t frame_received;
    uint8_t frame_opcode;
    bool message_active;
} Esp32WebsocketState;

bool Esp32WebsocketStateInit(Esp32WebsocketState *state, WebsocketCallback callback, void *callback_ctx);
void Esp32WebsocketStateDeinit(Esp32WebsocketState *state);

bool Esp32WebsocketStateIsClosed(const Esp32WebsocketState *state);
int32_t Esp32WebsocketStateGetCloseError(const Esp32WebsocketState *state);
void Esp32WebsocketStateMarkClosed(Esp32WebsocketState *state, int32_t close_error);
void Esp32WebsocketStateNotifyTerminal(Esp32WebsocketState *state,
                                       WebsocketCallbackType callback_type,
                                       int32_t close_error);

/**
 * Append one transport chunk of a WebSocket frame.
 *
 * frame_size and frame_offset describe the complete WebSocket frame, while
 * final_frame is the RFC 6455 FIN bit. Returns false for malformed, non-binary,
 * or over-sized messages. A completed message is delivered to the registered
 * callback before this function returns.
 */
bool Esp32WebsocketStateReceive(Esp32WebsocketState *state,
                                uint8_t opcode,
                                const uint8_t *data,
                                size_t data_size,
                                size_t frame_size,
                                size_t frame_offset,
                                bool final_frame);

#ifdef __cplusplus
}
#endif

#endif  // PORT_ESP32_WEBSOCKET_WEBSOCKET_ESP32_COMMON_H_
