#include "platform/linux/quic/quic_connection.h"

#include "platform/linux/clock/clock.h"

#include <string.h>

#include <picotls/openssl.h>

#define NO_STREAM (-1)
#define LOCAL_CID_LIST_MAX 32
#define MAX_DATAGRAM_FRAME_SIZE 1350
#define IDLE_TIMEOUT (6 * NGTCP2_SECONDS)
#define KEEP_ALIVE_TIMEOUT (2 * NGTCP2_SECONDS)
#define HANDSHAKE_TIMEOUT (10 * NGTCP2_SECONDS)
/* Flow-control windows sized for the reliable data plane: on a high-RTT link
 * peak stream throughput is the in-flight window / RTT, so a small window
 * throttles bulk transfers far below TCP, whose receive window autotunes to the
 * bandwidth-delay product. The per-stream window matches the reliable TX ring;
 * the connection window covers several concurrent reliable streams. */
#define INITIAL_MAX_DATA (1024 * 1024)
#define INITIAL_MAX_STREAM_DATA (64 * 1024)
#define INITIAL_MAX_STREAMS_BIDI 16
#define INITIAL_RTT (50 * NGTCP2_MILLISECONDS)
#define MAX_TX_UDP_PAYLOAD 1452

static ngtcp2_conn *getConnection(ngtcp2_crypto_conn_ref *connection_ref);
static void buildCallbacks(ngtcp2_callbacks *callbacks, bool is_server);
static void buildSettings(ngtcp2_settings *settings);
static void buildParams(ngtcp2_transport_params *params);
static void randomCid(ngtcp2_cid *cid);
static void randCallback(uint8_t *destination, size_t destination_length, const ngtcp2_rand_ctx *rand_context);
static int getNewConnectionIdCallback(
    ngtcp2_conn *connection,
    ngtcp2_cid *cid,
    uint8_t *token,
    size_t cid_length,
    void *user_data
);
static int handshakeCompletedCallback(ngtcp2_conn *connection, void *user_data);
static int receiveDatagramCallback(
    ngtcp2_conn *connection,
    uint32_t flags,
    const uint8_t *data,
    size_t data_length,
    void *user_data
);
static int receiveStreamDataCallback(
    ngtcp2_conn *connection,
    uint32_t flags,
    int64_t stream_id,
    uint64_t stream_offset,
    const uint8_t *data,
    size_t data_length,
    void *user_data,
    void *stream_user_data
);
static int ackedStreamDataOffsetCallback(
    ngtcp2_conn *connection,
    int64_t stream_id,
    uint64_t stream_offset,
    uint64_t data_length,
    void *user_data,
    void *stream_user_data
);

/* ---------- public ---------- */

void QuicConnection_Bind(QuicConnection *self, const QuicConnectionEvents *events)
{
    memset(self, 0, sizeof(*self));
    self->events = *events;
    self->connection_ref.get_conn = getConnection;
    self->connection_ref.user_data = self;
}

ngtcp2_crypto_conn_ref *QuicConnection_Ref(QuicConnection *self)
{
    return &self->connection_ref;
}

ngtcp2_conn *QuicConnection_Handle(QuicConnection *self)
{
    return self->connection;
}

TlsPeerCertificate *QuicConnection_PeerCertificate(QuicConnection *self)
{
    return &self->peer;
}

TlsPeerCertificate *QuicConnection_PeerCertificateOfSession(ptls_t *tls)
{
    ngtcp2_crypto_conn_ref *reference = *ptls_get_data_ptr(tls);
    QuicConnection *self = reference->user_data;

    return &self->peer;
}

bool QuicConnection_Open(QuicConnection *self, ngtcp2_crypto_picotls_ctx *tls_context, const ngtcp2_path *path)
{
    ngtcp2_callbacks callbacks;
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    ngtcp2_cid destination_cid;
    ngtcp2_cid source_cid;
    int result;

    buildCallbacks(&callbacks, false);
    buildSettings(&settings);
    buildParams(&params);
    randomCid(&destination_cid);
    randomCid(&source_cid);

    result = ngtcp2_conn_client_new(
        &self->connection,
        &destination_cid,
        &source_cid,
        path,
        NGTCP2_PROTO_VER_V1,
        &callbacks,
        &settings,
        &params,
        NULL,
        self
    );
    if (result != 0) {
        return false;
    }

    ngtcp2_conn_set_tls_native_handle(self->connection, tls_context);
    ngtcp2_conn_set_keep_alive_timeout(self->connection, KEEP_ALIVE_TIMEOUT);

    return true;
}

bool QuicConnection_OpenServer(
    QuicConnection *self,
    ngtcp2_crypto_picotls_ctx *tls_context,
    const ngtcp2_path *path,
    const ngtcp2_pkt_hd *initial_header
)
{
    ngtcp2_callbacks callbacks;
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    ngtcp2_cid source_cid;
    int result;

    buildCallbacks(&callbacks, true);
    buildSettings(&settings);
    buildParams(&params);
    params.original_dcid = initial_header->dcid;
    params.original_dcid_present = 1;
    randomCid(&source_cid);

    result = ngtcp2_conn_server_new(
        &self->connection,
        &initial_header->scid,
        &source_cid,
        path,
        initial_header->version,
        &callbacks,
        &settings,
        &params,
        NULL,
        self
    );
    if (result != 0) {
        return false;
    }

    ngtcp2_conn_set_tls_native_handle(self->connection, tls_context);

    return true;
}

void QuicConnection_Close(QuicConnection *self)
{
    if (self->connection == NULL) {
        return;
    }

    ngtcp2_conn_del(self->connection);
    self->connection = NULL;
}

bool QuicConnection_IsOpen(const QuicConnection *self)
{
    return self->connection != NULL;
}

bool QuicConnection_HasLocalCid(const QuicConnection *self, const ngtcp2_cid *cid)
{
    ngtcp2_cid local_cids[LOCAL_CID_LIST_MAX];
    size_t count;
    size_t i;

    if (self->connection == NULL) {
        return false;
    }

    count = ngtcp2_conn_get_scid2(self->connection, NULL);
    if (count > LOCAL_CID_LIST_MAX) {
        return false;
    }
    ngtcp2_conn_get_scid2(self->connection, local_cids);

    for(i=0; i<count; i++) {
        if (ngtcp2_cid_eq(&local_cids[i], cid)) {
            return true;
        }
    }

    return false;
}

bool QuicConnection_ReadPacket(QuicConnection *self, const ngtcp2_path *path, const uint8_t *data, size_t size)
{
    ngtcp2_pkt_info packet_info = { 0 };

    return ngtcp2_conn_read_pkt(self->connection, path, &packet_info, data, size, Clock_MonotonicNs()) == 0;
}

bool QuicConnection_HandleExpiry(QuicConnection *self)
{
    return ngtcp2_conn_handle_expiry(self->connection, Clock_MonotonicNs()) == 0;
}

uint64_t QuicConnection_NextExpiryNs(const QuicConnection *self)
{
    return ngtcp2_conn_get_expiry(self->connection);
}

bool QuicConnection_OpenControlStream(QuicConnection *self, int64_t *stream_id)
{
    return ngtcp2_conn_open_bidi_stream(self->connection, stream_id, NULL) == 0;
}

void QuicConnection_ExtendStreamCredit(QuicConnection *self, int64_t stream_id, size_t size)
{
    ngtcp2_conn_extend_max_stream_offset(self->connection, stream_id, size);
    ngtcp2_conn_extend_max_offset(self->connection, size);
}

ngtcp2_ssize QuicConnection_WriteDatagram(
    QuicConnection *self,
    uint8_t *packet_buffer,
    size_t packet_buffer_size,
    const uint8_t *payload,
    size_t payload_size,
    bool *accepted
)
{
    ngtcp2_vec data_vector = { (uint8_t *)payload, payload_size };
    ngtcp2_path_storage path_storage;
    ngtcp2_pkt_info packet_info;
    ngtcp2_ssize bytes_written;
    int accepted_flag = 0;

    ngtcp2_path_storage_zero(&path_storage);
    bytes_written = ngtcp2_conn_writev_datagram(
        self->connection,
        &path_storage.path,
        &packet_info,
        packet_buffer,
        packet_buffer_size,
        &accepted_flag,
        NGTCP2_WRITE_DATAGRAM_FLAG_NONE,
        ++self->next_datagram_id,
        &data_vector,
        1,
        Clock_MonotonicNs()
    );

    *accepted = accepted_flag != 0;

    return bytes_written;
}

ngtcp2_ssize QuicConnection_WriteStream(
    QuicConnection *self,
    uint8_t *packet_buffer,
    size_t packet_buffer_size,
    int64_t stream_id,
    const uint8_t *data,
    size_t data_size,
    size_t *consumed
)
{
    ngtcp2_vec data_vector = { (uint8_t *)data, data_size };
    ngtcp2_path_storage path_storage;
    ngtcp2_pkt_info packet_info;
    ngtcp2_ssize bytes_written;
    ngtcp2_ssize stream_bytes_consumed = 0;

    ngtcp2_path_storage_zero(&path_storage);
    bytes_written = ngtcp2_conn_writev_stream(
        self->connection,
        &path_storage.path,
        &packet_info,
        packet_buffer,
        packet_buffer_size,
        &stream_bytes_consumed,
        NGTCP2_WRITE_STREAM_FLAG_NONE,
        stream_id,
        &data_vector,
        data == NULL ? 0 : 1,
        Clock_MonotonicNs()
    );

    *consumed = stream_bytes_consumed > 0 ? (size_t)stream_bytes_consumed : 0;

    return bytes_written;
}

ngtcp2_ssize QuicConnection_WritePacket(QuicConnection *self, uint8_t *packet_buffer, size_t packet_buffer_size)
{
    size_t ignored;

    return QuicConnection_WriteStream(self, packet_buffer, packet_buffer_size, NO_STREAM, NULL, 0, &ignored);
}

ngtcp2_ssize QuicConnection_WriteConnectionClose(QuicConnection *self, uint8_t *packet_buffer, size_t packet_buffer_size)
{
    ngtcp2_path_storage path_storage;
    ngtcp2_pkt_info packet_info;
    ngtcp2_ccerr connection_close_error;

    ngtcp2_path_storage_zero(&path_storage);
    ngtcp2_ccerr_default(&connection_close_error);

    return ngtcp2_conn_write_connection_close(
        self->connection,
        &path_storage.path,
        &packet_info,
        packet_buffer,
        packet_buffer_size,
        &connection_close_error,
        Clock_MonotonicNs()
    );
}

/* ---------- private ---------- */

static ngtcp2_conn *getConnection(ngtcp2_crypto_conn_ref *connection_ref)
{
    QuicConnection *self = connection_ref->user_data;

    return self->connection;
}

static void buildCallbacks(ngtcp2_callbacks *callbacks, bool is_server)
{
    memset(callbacks, 0, sizeof(*callbacks));
    callbacks->recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks->encrypt = ngtcp2_crypto_encrypt_cb;
    callbacks->decrypt = ngtcp2_crypto_decrypt_cb;
    callbacks->hp_mask = ngtcp2_crypto_hp_mask_cb;
    callbacks->rand = randCallback;
    callbacks->get_new_connection_id = getNewConnectionIdCallback;
    callbacks->update_key = ngtcp2_crypto_update_key_cb;
    callbacks->delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks->delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks->get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
    callbacks->version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    callbacks->handshake_completed = handshakeCompletedCallback;
    callbacks->recv_datagram = receiveDatagramCallback;
    callbacks->recv_stream_data = receiveStreamDataCallback;
    callbacks->acked_stream_data_offset = ackedStreamDataOffsetCallback;

    if (is_server) {
        callbacks->recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
    } else {
        callbacks->client_initial = ngtcp2_crypto_client_initial_cb;
        callbacks->recv_retry = ngtcp2_crypto_recv_retry_cb;
    }
}

static void buildSettings(ngtcp2_settings *settings)
{
    ngtcp2_settings_default(settings);
    settings->initial_ts = Clock_MonotonicNs();
    settings->handshake_timeout = HANDSHAKE_TIMEOUT;
    /* The 333 ms default initial_rtt seeds loss detection and the pacer ~6x too
     * high for these links, so early loss is recovered late (tail spikes) and the
     * pacer ramps slowly. Seed a network-scale RTT; ngtcp2 adapts on the first
     * sample. Cap the payload at the Ethernet MSS but keep size shaping on so the
     * connection starts at the conservative 1200-byte size and PMTUD grows it to
     * the cap: a path whose MTU is below 1500 (tunnels, 1450-MTU links) would
     * otherwise blackhole every full-MSS packet and stall the handshake. */
    settings->initial_rtt = INITIAL_RTT;
    settings->max_tx_udp_payload_size = MAX_TX_UDP_PAYLOAD;
}

static void buildParams(ngtcp2_transport_params *params)
{
    ngtcp2_transport_params_default(params);
    params->initial_max_data = INITIAL_MAX_DATA;
    params->initial_max_stream_data_bidi_local = INITIAL_MAX_STREAM_DATA;
    params->initial_max_stream_data_bidi_remote = INITIAL_MAX_STREAM_DATA;
    params->initial_max_streams_bidi = INITIAL_MAX_STREAMS_BIDI;
    params->max_idle_timeout = IDLE_TIMEOUT;
    params->max_datagram_frame_size = MAX_DATAGRAM_FRAME_SIZE;
}

static void randomCid(ngtcp2_cid *cid)
{
    ptls_openssl_random_bytes(cid->data, QUIC_CONNECTION_CID_LENGTH);
    cid->datalen = QUIC_CONNECTION_CID_LENGTH;
}

static void randCallback(uint8_t *destination, size_t destination_length, const ngtcp2_rand_ctx *rand_context)
{
    (void)rand_context;

    ptls_openssl_random_bytes(destination, destination_length);
}

static int getNewConnectionIdCallback(
    ngtcp2_conn *connection,
    ngtcp2_cid *cid,
    uint8_t *token,
    size_t cid_length,
    void *user_data
)
{
    (void)connection;
    (void)user_data;

    ptls_openssl_random_bytes(cid->data, cid_length);
    cid->datalen = cid_length;
    ptls_openssl_random_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);

    return 0;
}

static int handshakeCompletedCallback(ngtcp2_conn *connection, void *user_data)
{
    QuicConnection *self = user_data;

    (void)connection;

    self->events.on_handshake_completed(self->events.context);

    return 0;
}

static int receiveDatagramCallback(
    ngtcp2_conn *connection,
    uint32_t flags,
    const uint8_t *data,
    size_t data_length,
    void *user_data
)
{
    QuicConnection *self = user_data;

    (void)connection;
    (void)flags;

    self->events.on_datagram(self->events.context, data, data_length);

    return 0;
}

static int receiveStreamDataCallback(
    ngtcp2_conn *connection,
    uint32_t flags,
    int64_t stream_id,
    uint64_t stream_offset,
    const uint8_t *data,
    size_t data_length,
    void *user_data,
    void *stream_user_data
)
{
    QuicConnection *self = user_data;

    (void)connection;
    (void)flags;
    (void)stream_offset;
    (void)stream_user_data;

    self->events.on_stream_data(self->events.context, stream_id, data, data_length);

    return 0;
}

static int ackedStreamDataOffsetCallback(
    ngtcp2_conn *connection,
    int64_t stream_id,
    uint64_t stream_offset,
    uint64_t data_length,
    void *user_data,
    void *stream_user_data
)
{
    QuicConnection *self = user_data;

    (void)connection;
    (void)stream_user_data;

    self->events.on_stream_acked(self->events.context, stream_id, stream_offset + data_length);

    return 0;
}
