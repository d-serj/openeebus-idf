/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "websocket_esp32_common.h"

#include <string.h>

#include "src/common/eebus_malloc.h"

bool Esp32WebsocketStateInit(Esp32WebsocketState *state, WebsocketCallback callback, void *callback_ctx) {
    memset(state, 0, sizeof(*state));
    state->callback = callback;
    state->callback_ctx = callback_ctx;
    state->mutex = xSemaphoreCreateMutex();
    return state->mutex != NULL;
}

void Esp32WebsocketStateDeinit(Esp32WebsocketState *state) {
    if (state->mutex != NULL) {
        xSemaphoreTake(state->mutex, portMAX_DELAY);
    }

    state->callback = NULL;
    EEBUS_FREE(state->rx_buffer);
    state->rx_buffer = NULL;
    state->rx_size = 0;

    if (state->mutex != NULL) {
        SemaphoreHandle_t mutex = state->mutex;
        state->mutex = NULL;
        xSemaphoreGive(mutex);
        vSemaphoreDelete(mutex);
    }
}

bool Esp32WebsocketStateIsClosed(const Esp32WebsocketState *state) {
    Esp32WebsocketState *mutable_state = (Esp32WebsocketState *)state;
    if (mutable_state->mutex == NULL) {
        return true;
    }

    xSemaphoreTake(mutable_state->mutex, portMAX_DELAY);
    const bool closed = mutable_state->closed;
    xSemaphoreGive(mutable_state->mutex);

    return closed;
}

int32_t Esp32WebsocketStateGetCloseError(const Esp32WebsocketState *state) {
    Esp32WebsocketState *mutable_state = (Esp32WebsocketState *)state;
    if (mutable_state->mutex == NULL) {
        return state->close_error;
    }

    xSemaphoreTake(mutable_state->mutex, portMAX_DELAY);
    const int32_t close_error = mutable_state->close_error;
    xSemaphoreGive(mutable_state->mutex);

    return close_error;
}

void Esp32WebsocketStateMarkClosed(Esp32WebsocketState *state, int32_t close_error) {
    if (state->mutex == NULL) {
        return;
    }

    xSemaphoreTake(state->mutex, portMAX_DELAY);
    state->closed = true;
    state->close_error = close_error;
    xSemaphoreGive(state->mutex);
}

void Esp32WebsocketStateNotifyTerminal(Esp32WebsocketState *state,
                                       WebsocketCallbackType callback_type,
                                       int32_t close_error) {
    WebsocketCallback callback = NULL;
    void *callback_ctx = NULL;

    if (state->mutex == NULL) {
        return;
    }

    xSemaphoreTake(state->mutex, portMAX_DELAY);
    state->closed = true;
    if (!state->terminal_notified) {
        state->terminal_notified = true;
        state->close_error = close_error;
        callback = state->callback;
        callback_ctx = state->callback_ctx;
    }
    xSemaphoreGive(state->mutex);

    if (callback != NULL) {
        callback(callback_type, NULL, 0, callback_ctx);
    }
}

static bool AppendData(Esp32WebsocketState *state, const uint8_t *data, size_t data_size) {
    if ((data_size > EEBUS_WEBSOCKET_MAX_INPUT_MSG_SIZE)
        || (state->rx_size > EEBUS_WEBSOCKET_MAX_INPUT_MSG_SIZE - data_size)) {
        return false;
    }
    if (data_size == 0) {
        return true;
    }
    if (data == NULL) {
        return false;
    }

    uint8_t *const buffer = EEBUS_MALLOC(state->rx_size + data_size);
    if (buffer == NULL) {
        return false;
    }
    if (state->rx_buffer != NULL) {
        memcpy(buffer, state->rx_buffer, state->rx_size);
    }
    memcpy(buffer + state->rx_size, data, data_size);
    EEBUS_FREE(state->rx_buffer);
    state->rx_buffer = buffer;
    state->rx_size += data_size;
    return true;
}

static void ResetReceive(Esp32WebsocketState *state) {
    EEBUS_FREE(state->rx_buffer);
    state->rx_buffer = NULL;
    state->rx_size = 0;
    state->frame_size = 0;
    state->frame_received = 0;
    state->frame_opcode = 0;
    state->message_active = false;
}

bool Esp32WebsocketStateReceive(Esp32WebsocketState *state,
                                uint8_t opcode,
                                const uint8_t *data,
                                size_t data_size,
                                size_t frame_size,
                                size_t frame_offset,
                                bool final_frame) {
    WebsocketCallback callback = NULL;
    void *callback_ctx = NULL;
    uint8_t *completed_message = NULL;
    size_t completed_size = 0;
    bool valid = true;

    if (state->mutex == NULL) {
        return false;
    }
    xSemaphoreTake(state->mutex, portMAX_DELAY);

    if (state->closed || (frame_size > EEBUS_WEBSOCKET_MAX_INPUT_MSG_SIZE - state->rx_size)
        || (frame_offset > frame_size) || (data_size > frame_size - frame_offset)) {
        valid = false;
        goto done;
    }

    if (frame_offset == 0) {
        if (((opcode == kEsp32WebsocketOpcodeBinary) && state->message_active)
            || ((opcode == kEsp32WebsocketOpcodeContinuation) && !state->message_active)
            || ((opcode != kEsp32WebsocketOpcodeBinary) && (opcode != kEsp32WebsocketOpcodeContinuation))) {
            valid = false;
            goto done;
        }
        state->frame_size = frame_size;
        state->frame_received = 0;
        state->frame_opcode = opcode;
    } else if ((frame_size != state->frame_size) || (frame_offset != state->frame_received)
               || (opcode != state->frame_opcode)) {
        valid = false;
        goto done;
    }

    if (!AppendData(state, data, data_size)) {
        valid = false;
        goto done;
    }
    state->frame_received += data_size;

    if (state->frame_received == state->frame_size) {
        if (final_frame) {
            completed_message = state->rx_buffer;
            completed_size = state->rx_size;
            state->rx_buffer = NULL;
            state->rx_size = 0;
            state->message_active = false;
            callback = state->callback;
            callback_ctx = state->callback_ctx;
        } else {
            state->message_active = true;
        }
        state->frame_size = 0;
        state->frame_received = 0;
        state->frame_opcode = 0;
    }

done:
    if (!valid) {
        ResetReceive(state);
    }
    xSemaphoreGive(state->mutex);

    if (valid && (callback != NULL)) {
        callback(kWebsocketCallbackTypeRead, completed_message, completed_size, callback_ctx);
    }
    EEBUS_FREE(completed_message);
    return valid;
}
