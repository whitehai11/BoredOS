// Copyright (c) 2026 maro (mail@mgoth.de)
// This software is released under the GNU General Public License v3.0. See LICENSE file for details.
// This header needs to maintain in any file it is present in, as per the GPL license terms.

// lwIP altcp <-> mbedTLS 3.6.2 glue. TLS 1.2 client only, no POSIX.

#include "lwip/opt.h"

#if LWIP_ALTCP && LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_MBEDTLS

#include "lwip/altcp.h"
#include "lwip/altcp_tls.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"
#include <stddef.h>
#include <stdint.h>

void *kmalloc(size_t size);
void  kfree(void *ptr);
void *memset(void *s, int c, size_t n);

#include "lwip/priv/altcp_priv.h"
#include "lwip/altcp_tcp.h"

struct altcp_tls_config {
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509_crt         ca;
    int                      entropy_inited;
};

typedef struct altcp_mbedtls_state_s {
    struct altcp_tls_config *conf;
    mbedtls_ssl_context      ssl;
    mbedtls_ssl_config       ssl_conf;
    struct pbuf             *rx;
    size_t                   rx_offset;
    uint8_t                  handshake_done;
    uint8_t                  closed;
} altcp_mbedtls_state_t;


static err_t altcp_mbedtls_do_handshake(struct altcp_pcb *conn,
                                         altcp_mbedtls_state_t *state);
static err_t altcp_mbedtls_handle_rx(struct altcp_pcb *conn,
                                      altcp_mbedtls_state_t *state);

static err_t altcp_mbedtls_lower_connected(void *arg,
                                            struct altcp_pcb *inner,
                                            err_t err);
static err_t altcp_mbedtls_lower_recv(void *arg, struct altcp_pcb *inner,
                                       struct pbuf *p, err_t err);
static err_t altcp_mbedtls_lower_sent(void *arg, struct altcp_pcb *inner,
                                       u16_t len);
static void  altcp_mbedtls_lower_err(void *arg, err_t err);

static void  altcp_mbedtls_set_poll(struct altcp_pcb *conn, u8_t interval);
static void  altcp_mbedtls_recved(struct altcp_pcb *conn, u16_t len);
static err_t altcp_mbedtls_bind(struct altcp_pcb *conn,
                                 const ip_addr_t *ipaddr, u16_t port);
static err_t altcp_mbedtls_connect(struct altcp_pcb *conn,
                                    const ip_addr_t *ipaddr, u16_t port,
                                    altcp_connected_fn connected);
static struct altcp_pcb *altcp_mbedtls_listen(struct altcp_pcb *conn,
                                               u8_t backlog, err_t *err);
static void  altcp_mbedtls_abort(struct altcp_pcb *conn);
static err_t altcp_mbedtls_close(struct altcp_pcb *conn);
static err_t altcp_mbedtls_shutdown(struct altcp_pcb *conn,
                                     int shut_rx, int shut_tx);
static err_t altcp_mbedtls_write(struct altcp_pcb *conn,
                                  const void *dataptr, u16_t len,
                                  u8_t apiflags);
static err_t altcp_mbedtls_output(struct altcp_pcb *conn);
static u16_t altcp_mbedtls_mss(struct altcp_pcb *conn);
static u16_t altcp_mbedtls_sndbuf(struct altcp_pcb *conn);
static u16_t altcp_mbedtls_sndqueuelen(struct altcp_pcb *conn);
static void  altcp_mbedtls_nagle_disable(struct altcp_pcb *conn);
static void  altcp_mbedtls_nagle_enable(struct altcp_pcb *conn);
static int   altcp_mbedtls_nagle_disabled(struct altcp_pcb *conn);
static void  altcp_mbedtls_setprio(struct altcp_pcb *conn, u8_t prio);
static void  altcp_mbedtls_dealloc(struct altcp_pcb *conn);
static err_t altcp_mbedtls_get_tcp_addrinfo(struct altcp_pcb *conn,
                                              int local, ip_addr_t *addr,
                                              u16_t *port);
static ip_addr_t *altcp_mbedtls_get_ip(struct altcp_pcb *conn, int local);
static u16_t altcp_mbedtls_get_port(struct altcp_pcb *conn, int local);


static const struct altcp_functions altcp_mbedtls_functions = {
    altcp_mbedtls_set_poll,
    altcp_mbedtls_recved,
    altcp_mbedtls_bind,
    altcp_mbedtls_connect,
    altcp_mbedtls_listen,
    altcp_mbedtls_abort,
    altcp_mbedtls_close,
    altcp_mbedtls_shutdown,
    altcp_mbedtls_write,
    altcp_mbedtls_output,
    altcp_mbedtls_mss,
    altcp_mbedtls_sndbuf,
    altcp_mbedtls_sndqueuelen,
    altcp_mbedtls_nagle_disable,
    altcp_mbedtls_nagle_enable,
    altcp_mbedtls_nagle_disabled,
    altcp_mbedtls_setprio,
    altcp_mbedtls_dealloc,
    altcp_mbedtls_get_tcp_addrinfo,
    altcp_mbedtls_get_ip,
    altcp_mbedtls_get_port,
};


static void altcp_mbedtls_setup_inner_callbacks(struct altcp_pcb *inner,
                                                  struct altcp_pcb *outer)
{
    altcp_arg(inner, outer);
    altcp_recv(inner, altcp_mbedtls_lower_recv);
    altcp_sent(inner, altcp_mbedtls_lower_sent);
    altcp_err(inner, altcp_mbedtls_lower_err);
}


struct altcp_tls_config *altcp_tls_create_config_client(const u8_t *cert,
                                                          size_t cert_len)
{
    struct altcp_tls_config *conf =
        (struct altcp_tls_config *)kmalloc(sizeof(struct altcp_tls_config));
    if (!conf) {
        return NULL;
    }
    memset(conf, 0, sizeof(struct altcp_tls_config));

    mbedtls_entropy_init(&conf->entropy);
    mbedtls_ctr_drbg_init(&conf->ctr_drbg);

    if (mbedtls_ctr_drbg_seed(&conf->ctr_drbg, mbedtls_entropy_func,
                               &conf->entropy, NULL, 0) != 0) {
        mbedtls_ctr_drbg_free(&conf->ctr_drbg);
        mbedtls_entropy_free(&conf->entropy);
        kfree(conf);
        return NULL;
    }
    conf->entropy_inited = 1;

    mbedtls_x509_crt_init(&conf->ca);
    if (cert != NULL && cert_len > 0) {
        // +1 for NUL terminator needed by mbedtls when parsing PEM
        mbedtls_x509_crt_parse(&conf->ca, cert, cert_len + 1);
    }

    return conf;
}

void altcp_tls_free_config(struct altcp_tls_config *conf)
{
    if (!conf)
        return;
    mbedtls_x509_crt_free(&conf->ca);
    if (conf->entropy_inited) {
        mbedtls_ctr_drbg_free(&conf->ctr_drbg);
        mbedtls_entropy_free(&conf->entropy);
    }
    kfree(conf);
}

void altcp_tls_free_entropy(void)
{
    // entropy lives in the config struct, freed by altcp_tls_free_config()
}

// server-side TLS not supported

struct altcp_tls_config *altcp_tls_create_config_server(uint8_t cert_count)
{
    (void)cert_count;
    return NULL;
}

err_t altcp_tls_config_server_add_privkey_cert(
    struct altcp_tls_config *config,
    const u8_t *privkey, size_t privkey_len,
    const u8_t *privkey_pass, size_t privkey_pass_len,
    const u8_t *cert, size_t cert_len)
{
    (void)config; (void)privkey; (void)privkey_len;
    (void)privkey_pass; (void)privkey_pass_len;
    (void)cert; (void)cert_len;
    return ERR_VAL;
}

struct altcp_tls_config *altcp_tls_create_config_server_privkey_cert(
    const u8_t *privkey, size_t privkey_len,
    const u8_t *privkey_pass, size_t privkey_pass_len,
    const u8_t *cert, size_t cert_len)
{
    (void)privkey; (void)privkey_len;
    (void)privkey_pass; (void)privkey_pass_len;
    (void)cert; (void)cert_len;
    return NULL;
}

struct altcp_tls_config *altcp_tls_create_config_client_2wayauth(
    const u8_t *ca, size_t ca_len,
    const u8_t *privkey, size_t privkey_len,
    const u8_t *privkey_pass, size_t privkey_pass_len,
    const u8_t *cert, size_t cert_len)
{
    (void)ca; (void)ca_len;
    (void)privkey; (void)privkey_len;
    (void)privkey_pass; (void)privkey_pass_len;
    (void)cert; (void)cert_len;
    return NULL;
}

// BIO send: pass encrypted bytes to inner TCP
static int altcp_mbedtls_bio_send(void *ctx, const unsigned char *buf,
                                   size_t len)
{
    struct altcp_pcb *conn = (struct altcp_pcb *)ctx;
    struct altcp_pcb *inner = conn->inner_conn;
    err_t err;

    if (!inner || len == 0) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }

    u16_t write_len = (len > 0xFFFFu) ? 0xFFFFu : (u16_t)len;

    err = altcp_write(inner, buf, write_len, TCP_WRITE_FLAG_COPY);
    if (err != ERR_OK) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    altcp_output(inner);
    return (int)write_len;
}

// BIO recv: feed rx pbuf data into mbedTLS
static int altcp_mbedtls_bio_recv(void *ctx, unsigned char *buf, size_t len)
{
    struct altcp_pcb *conn = (struct altcp_pcb *)ctx;
    altcp_mbedtls_state_t *state = (altcp_mbedtls_state_t *)conn->state;
    size_t copied = 0;

    if (!state || !state->rx) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    while (copied < len && state->rx != NULL) {
        struct pbuf *p = state->rx;
        size_t available = (size_t)p->len - state->rx_offset;
        size_t take = len - copied;
        const uint8_t *src;

        if (take > available) {
            take = available;
        }

        src = (const uint8_t *)p->payload + state->rx_offset;
        {
            size_t i;
            for (i = 0; i < take; i++) {
                buf[copied + i] = src[i];
            }
        }
        copied += take;
        state->rx_offset += take;

        if (state->rx_offset >= (size_t)p->len) {
            struct pbuf *next = p->next;
            if (next)
                pbuf_ref(next);
            p->next = NULL;
            pbuf_free(p);
            state->rx = next;
            state->rx_offset = 0;
        }
    }

    if (copied == 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    // advance TCP window or server stops sending and handshake stalls
    if (conn->inner_conn)
        altcp_recved(conn->inner_conn, (u16_t)copied);

    return (int)copied;
}


static err_t altcp_mbedtls_do_handshake(struct altcp_pcb *conn,
                                          altcp_mbedtls_state_t *state)
{
    int ret = mbedtls_ssl_handshake(&state->ssl);

    if (ret == 0) {
        state->handshake_done = 1;
        if (conn->connected)
            return conn->connected(conn->arg, conn, ERR_OK);
        return ERR_OK;
    }

    if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
        ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return ERR_OK;
    }

    // fatal — kill inner TCP so no more data arrives
    state->closed = 1;
    if (conn->inner_conn != NULL) {
        altcp_abort(conn->inner_conn);
        conn->inner_conn = NULL;
    }
    if (conn->err)
        conn->err(conn->arg, ERR_VAL);
    return ERR_VAL;
}

static err_t altcp_mbedtls_handle_rx(struct altcp_pcb *conn,
                                       altcp_mbedtls_state_t *state)
{
    err_t err;

    if (!state->handshake_done) {
        err = altcp_mbedtls_do_handshake(conn, state);
        if (!state->handshake_done)
            return err;
    }

    // drain decrypted app data
    for (;;) {
        unsigned char tmp[1460];
        int ret = mbedtls_ssl_read(&state->ssl, tmp, sizeof(tmp));

        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            break;
        }

        if (ret == 0 || ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ||
            ret == MBEDTLS_ERR_SSL_CONN_EOF) {
            state->closed = 1;
            if (conn->recv)
                conn->recv(conn->arg, conn, NULL, ERR_OK);
            break;
        }

        if (ret < 0) {
            state->closed = 1;
            if (conn->err)
                conn->err(conn->arg, ERR_VAL);
            return ERR_VAL;
        }

        if (conn->recv != NULL) {
            struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)ret, PBUF_RAM);
            if (p) {
                u16_t i;
                uint8_t *dst = (uint8_t *)p->payload;
                for (i = 0; i < (u16_t)ret; i++)
                    dst[i] = tmp[i];
                err = conn->recv(conn->arg, conn, p, ERR_OK);
                if (err != ERR_OK) {
                    pbuf_free(p);
                    return err;
                }
            }
            // pbuf_alloc failed -> drop data, kernel OOM
        }
    }

    return ERR_OK;
}


static err_t altcp_mbedtls_lower_connected(void *arg,
                                             struct altcp_pcb *inner,
                                             err_t err)
{
    struct altcp_pcb *conn = (struct altcp_pcb *)arg;
    altcp_mbedtls_state_t *state;

    (void)inner;

    if (!conn)
        return ERR_VAL;
    state = (altcp_mbedtls_state_t *)conn->state;

    if (err != ERR_OK || !state) {
        if (conn->err)
            conn->err(conn->arg, err);
        return err;
    }

    // TCP up, start handshake
    return altcp_mbedtls_do_handshake(conn, state);
}

static err_t altcp_mbedtls_lower_recv(void *arg, struct altcp_pcb *inner,
                                        struct pbuf *p, err_t err)
{
    struct altcp_pcb *conn = (struct altcp_pcb *)arg;
    altcp_mbedtls_state_t *state;

    (void)inner;

    if (!conn) {
        if (p) pbuf_free(p);
        return ERR_VAL;
    }
    state = (altcp_mbedtls_state_t *)conn->state;

    if (!p) {
        state->closed = 1;
        if (conn->recv)
            conn->recv(conn->arg, conn, NULL, ERR_OK);
        return ERR_OK;
    }

    if (err != ERR_OK) {
        pbuf_free(p);
        return err;
    }

    if (state->closed) {
        pbuf_free(p);
        return ERR_OK;
    }

    if (!state->rx)
        state->rx = p;
    else
        pbuf_cat(state->rx, p);

    return altcp_mbedtls_handle_rx(conn, state);
}

static err_t altcp_mbedtls_lower_sent(void *arg, struct altcp_pcb *inner,
                                        u16_t len)
{
    struct altcp_pcb *conn = (struct altcp_pcb *)arg;

    (void)inner;

    if (!conn)
        return ERR_VAL;
    if (conn->sent)
        return conn->sent(conn->arg, conn, len);
    return ERR_OK;
}

static void altcp_mbedtls_lower_err(void *arg, err_t err)
{
    struct altcp_pcb *conn = (struct altcp_pcb *)arg;
    altcp_mbedtls_state_t *state;

    if (!conn)
        return;
    state = (altcp_mbedtls_state_t *)conn->state;
    if (state)
        state->closed = 1;
    if (conn->err)
        conn->err(conn->arg, err);
}

static struct altcp_pcb *altcp_mbedtls_init(struct altcp_tls_config *config,
                                              struct altcp_pcb *inner_pcb)
{
    struct altcp_pcb *conn;
    altcp_mbedtls_state_t *state;

    if (!config || !inner_pcb)
        return NULL;

    conn = altcp_alloc();
    if (!conn)
        return NULL;

    state = (altcp_mbedtls_state_t *)kmalloc(sizeof(altcp_mbedtls_state_t));
    if (!state) {
        altcp_free(conn);
        return NULL;
    }
    memset(state, 0, sizeof(altcp_mbedtls_state_t));
    state->conf = config;

    mbedtls_ssl_init(&state->ssl);
    mbedtls_ssl_config_init(&state->ssl_conf);

    if (mbedtls_ssl_config_defaults(&state->ssl_conf,
                                     MBEDTLS_SSL_IS_CLIENT,
                                     MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        mbedtls_ssl_free(&state->ssl);
        mbedtls_ssl_config_free(&state->ssl_conf);
        kfree(state);
        altcp_free(conn);
        return NULL;
    }

    // TLS 1.2 only
    mbedtls_ssl_conf_min_tls_version(&state->ssl_conf,
                                      MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&state->ssl_conf,
                                      MBEDTLS_SSL_VERSION_TLS1_2);

    /* TODO: switch back to VERIFY_REQUIRED once CA bundle is complete */
    mbedtls_ssl_conf_authmode(&state->ssl_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&state->ssl_conf, &config->ca, NULL);
    mbedtls_ssl_conf_rng(&state->ssl_conf, mbedtls_ctr_drbg_random,
                          &config->ctr_drbg);

    if (mbedtls_ssl_setup(&state->ssl, &state->ssl_conf) != 0) {
        mbedtls_ssl_free(&state->ssl);
        mbedtls_ssl_config_free(&state->ssl_conf);
        kfree(state);
        altcp_free(conn);
        return NULL;
    }

    mbedtls_ssl_set_bio(&state->ssl, conn,
                         altcp_mbedtls_bio_send,
                         altcp_mbedtls_bio_recv,
                         NULL);

    conn->fns       = &altcp_mbedtls_functions;
    conn->inner_conn = inner_pcb;
    conn->state     = state;

    return conn;
}

// altcp_tls_new/altcp_tls_alloc are in altcp_alloc.c, they call altcp_tls_wrap()

struct altcp_pcb *altcp_tls_wrap(struct altcp_tls_config *config,
                                   struct altcp_pcb *inner_pcb)
{
    if (!config || !inner_pcb)
        return NULL;

    return altcp_mbedtls_init(config, inner_pcb);
}

void *altcp_tls_context(struct altcp_pcb *conn)
{
    altcp_mbedtls_state_t *st;

    if (!conn || !conn->state)
        return NULL;
    st = (altcp_mbedtls_state_t *)conn->state;
    return &st->ssl;
}


static void altcp_mbedtls_set_poll(struct altcp_pcb *conn, u8_t interval)
{
    if (conn->inner_conn)
        altcp_poll(conn->inner_conn, NULL, interval);
}

static void altcp_mbedtls_recved(struct altcp_pcb *conn, u16_t len)
{
    if (conn->inner_conn)
        altcp_recved(conn->inner_conn, len);
}

static err_t altcp_mbedtls_bind(struct altcp_pcb *conn,
                                  const ip_addr_t *ipaddr, u16_t port)
{
    if (!conn->inner_conn)
        return ERR_VAL;
    return altcp_bind(conn->inner_conn, ipaddr, port);
}

static err_t altcp_mbedtls_connect(struct altcp_pcb *conn,
                                     const ip_addr_t *ipaddr, u16_t port,
                                     altcp_connected_fn connected)
{
    if (!conn || !conn->inner_conn)
        return ERR_VAL;
    (void)conn->state; /* state not needed here; SNI set by application */

    conn->connected = connected;
    altcp_mbedtls_setup_inner_callbacks(conn->inner_conn, conn);
    // TCP connect; handshake starts in lower_connected callback
    return altcp_connect(conn->inner_conn, ipaddr, port,
                          altcp_mbedtls_lower_connected);
}

static struct altcp_pcb *altcp_mbedtls_listen(struct altcp_pcb *conn,
                                                u8_t backlog, err_t *err)
{
    (void)conn; (void)backlog;
    if (err)
        *err = ERR_VAL;
    return NULL;
}

static void altcp_mbedtls_abort(struct altcp_pcb *conn)
{
    altcp_mbedtls_state_t *state;

    if (!conn)
        return;
    state = (altcp_mbedtls_state_t *)conn->state;
    if (state)
        state->closed = 1;
    if (conn->inner_conn != NULL) {
        altcp_abort(conn->inner_conn);
        conn->inner_conn = NULL;
    }
}

static err_t altcp_mbedtls_close(struct altcp_pcb *conn)
{
    altcp_mbedtls_state_t *state;
    err_t err;

    if (!conn)
        return ERR_VAL;
    state = (altcp_mbedtls_state_t *)conn->state;

    if (state && !state->closed && state->handshake_done)
        mbedtls_ssl_close_notify(&state->ssl);

    if (conn->inner_conn != NULL) {
        err = altcp_close(conn->inner_conn);
        conn->inner_conn = NULL;
        return err;
    }
    return ERR_OK;
}

static err_t altcp_mbedtls_shutdown(struct altcp_pcb *conn,
                                      int shut_rx, int shut_tx)
{
    if (!conn->inner_conn)
        return ERR_VAL;
    return altcp_shutdown(conn->inner_conn, shut_rx, shut_tx);
}

static err_t altcp_mbedtls_write(struct altcp_pcb *conn,
                                   const void *dataptr, u16_t len,
                                   u8_t apiflags)
{
    altcp_mbedtls_state_t *state;
    int ret;

    (void)apiflags;

    if (!conn || !conn->state)
        return ERR_VAL;
    state = (altcp_mbedtls_state_t *)conn->state;

    if (!state->handshake_done || state->closed)
        return ERR_VAL;

    ret = mbedtls_ssl_write(&state->ssl,
                             (const unsigned char *)dataptr,
                             (size_t)len);
    if (ret < 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            return ERR_WOULDBLOCK;
        }
        return ERR_VAL;
    }
    return ERR_OK;
}

static err_t altcp_mbedtls_output(struct altcp_pcb *conn)
{
    if (!conn->inner_conn)
        return ERR_VAL;
    return altcp_output(conn->inner_conn);
}

static u16_t altcp_mbedtls_mss(struct altcp_pcb *conn)
{
    if (!conn->inner_conn)
        return 0;
    return altcp_mss(conn->inner_conn);
}

static u16_t altcp_mbedtls_sndbuf(struct altcp_pcb *conn)
{
    if (!conn->inner_conn)
        return 0;
    return altcp_sndbuf(conn->inner_conn);
}

static u16_t altcp_mbedtls_sndqueuelen(struct altcp_pcb *conn)
{
    if (!conn->inner_conn)
        return 0;
    return altcp_sndqueuelen(conn->inner_conn);
}

static void altcp_mbedtls_nagle_disable(struct altcp_pcb *conn)
{
    if (conn->inner_conn)
        altcp_nagle_disable(conn->inner_conn);
}

static void altcp_mbedtls_nagle_enable(struct altcp_pcb *conn)
{
    if (conn->inner_conn)
        altcp_nagle_enable(conn->inner_conn);
}

static int altcp_mbedtls_nagle_disabled(struct altcp_pcb *conn)
{
    if (!conn->inner_conn)
        return 0;
    return altcp_nagle_disabled(conn->inner_conn);
}

static void altcp_mbedtls_setprio(struct altcp_pcb *conn, u8_t prio)
{
    if (conn->inner_conn)
        altcp_setprio(conn->inner_conn, prio);
}

static void altcp_mbedtls_dealloc(struct altcp_pcb *conn)
{
    altcp_mbedtls_state_t *state;

    if (!conn)
        return;
    state = (altcp_mbedtls_state_t *)conn->state;

    if (state) {
        if (state->rx) {
            pbuf_free(state->rx);
            state->rx = NULL;
        }
        mbedtls_ssl_free(&state->ssl);
        mbedtls_ssl_config_free(&state->ssl_conf);
        kfree(state);
        conn->state = NULL;
    }
}

static err_t altcp_mbedtls_get_tcp_addrinfo(struct altcp_pcb *conn,
                                              int local, ip_addr_t *addr,
                                              u16_t *port)
{
    if (!conn->inner_conn)
        return ERR_VAL;
    return altcp_get_tcp_addrinfo(conn->inner_conn, local, addr, port);
}

static ip_addr_t *altcp_mbedtls_get_ip(struct altcp_pcb *conn, int local)
{
    if (!conn->inner_conn)
        return NULL;
    return altcp_get_ip(conn->inner_conn, local);
}

static u16_t altcp_mbedtls_get_port(struct altcp_pcb *conn, int local)
{
    if (!conn->inner_conn)
        return 0;
    return altcp_get_port(conn->inner_conn, local);
}

#endif /* LWIP_ALTCP && LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_MBEDTLS */
