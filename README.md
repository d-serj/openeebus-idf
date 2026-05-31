# OpenEEBUS ESP-IDF component

This component builds the `openeebus` submodule with an ESP-IDF
WebSocket transport. Outbound connections use `esp_websocket_client`; inbound
SHIP connections use `esp_http_server` with a public-API `esp_tls` transport.

The consuming application must enable:

```text
CONFIG_HTTPD_WS_SUPPORT=y
CONFIG_ESP_TLS_SERVER_MIN_AUTH_MODE_OPTIONAL=y
CONFIG_ESP_TLS_INSECURE=y
CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY=y
CONFIG_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE=y
```

SHIP peers use self-signed certificates. TLS chain verification is therefore
disabled for the outbound handshake, but the connection is not upgraded to a
WebSocket until the adapter has calculated the server certificate's public-key
SKI and matched it exactly against OpenEEBUS' trusted remote SKI. The inbound
server requests a client certificate in optional-auth mode and passes its SKI
to OpenEEBUS' existing trust decision.
