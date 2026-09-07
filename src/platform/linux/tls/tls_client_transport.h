#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "platform/linux/tls/tls_channel.h"
#include "platform/linux/tls/tls_client_security.h"
#include "agent/ports/transport_events.h"
#include "agent/ports/transport_port.h"

#define TLS_CLIENT_HOST_MAX 256
#define TLS_CLIENT_PORT_TEXT_MAX 16

/*
 * TLS-over-TCP client transport: both planes share the single protected
 * stream. The TCP connect and the TLS handshake are both nonblocking;
 * on_connected fires once the handshake completes, which is also where the
 * TOFU pin of the hub is enforced (handshake fails on mismatch). The
 * connection fd is created per connect — the platform loop must re-register
 * it after each reconnect and watch EPOLLOUT while the channel wants to
 * write.
 */
typedef struct {
    TransportPort port;
    TransportEvents events;
    TlsClientSecurity security;
    char host[TLS_CLIENT_HOST_MAX];
    char port_text[TLS_CLIENT_PORT_TEXT_MAX];
    TlsChannel channel;
    int32_t fd;
    bool connecting;
    bool announced;
} TlsClientTransport;

bool TlsClientTransport_Init(
    TlsClientTransport *self,
    const char *host,
    const char *port,
    const TransportEvents *events,
    const TlsClientSecurityConfig *security_config
);
TransportPort *TlsClientTransport_Port(TlsClientTransport *self);
int32_t TlsClientTransport_Fd(const TlsClientTransport *self);
bool TlsClientTransport_WantsWritable(const TlsClientTransport *self);
void TlsClientTransport_OnReadable(TlsClientTransport *self);
void TlsClientTransport_OnWritable(TlsClientTransport *self);
