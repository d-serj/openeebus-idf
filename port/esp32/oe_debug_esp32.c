/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "src/common/debug.h"

#include <stdarg.h>

#include "esp_log.h"

static const char *kTag = "openeebus";

void DebugPrintf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    esp_log_writev(ESP_LOG_DEBUG, kTag, format, args);
    va_end(args);
}

void DebugHexdump(void *data, size_t data_size) {
    ESP_LOG_BUFFER_HEXDUMP(kTag, data, data_size, ESP_LOG_DEBUG);
}
