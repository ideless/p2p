#include "p2p.h"
#include "mt19937-64.h"
#include "yskey.h"
#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#define SUCCESS 0
#define EAGAIN -1
#define ERROR -2

void p2p_log(struct p2p_ctx *ctx, int verbose, const char *format, ...)
{
    if (ctx->logger == NULL || ctx->verbose < verbose) {
        return;
    }
    va_list argptr;
    va_start(argptr, format);
    vfprintf(ctx->logger, format, argptr);
    va_end(argptr);
}

void p2p_log_raw(struct p2p_ctx *ctx, int verbose, uint8_t *data, size_t length)
{
    if (ctx->logger == NULL || ctx->verbose < verbose || length == 0) {
        return;
    }
    for (size_t i = 0; i < length; ++i) {
        if (i == 0) {
            /* do nothing */
        } else if (i % 16 == 4 || i % 16 == 8 || i % 16 == 12) {
            printf("  ");
        } else if (i && i % 16 == 0) {
            printf("\n");
        } else {
            printf(" ");
        }
        printf("%02X", data[i]);
    }
    printf("\n");
}

void p2p_clear(struct p2p_ctx *ctx)
{
    free(ctx->key_buf);
    if (ctx->server != NULL) {
        ikcp_release(ctx->server);
    }
    if (ctx->client != NULL) {
        ikcp_release(ctx->client);
    }
    free(ctx->buf);
}

void p2p_init(struct p2p_ctx *ctx)
{
    ctx->key_buf = NULL;
    ctx->key_len = 0;
    ctx->override = 0;
    ctx->server = NULL;
    ctx->client = NULL;
    ctx->time = 0;
    ctx->cur = NULL;
    ctx->buf = NULL;
    ctx->buf_len = 0;
}

struct p2p_ctx *p2p_open(uint8_t *data, uint32_t length)
{
    struct p2p_ctx *ctx;

    ctx = malloc(sizeof *ctx);

    ctx->pfile = pcap_open(data, length);
    if (ctx->pfile == NULL) {
        free(ctx);
        return NULL;
    }

    p2p_init(ctx);

    ctx->logger = NULL;
    ctx->verbose = 0;

    return ctx;
}

void p2p_close(struct p2p_ctx *ctx)
{
    pcap_close(ctx->pfile);
    p2p_clear(ctx);
    free(ctx);
}

void p2p_pad_key(struct p2p_ctx *ctx, struct mt19937_64_ctx *mt, uint8_t le)
{
    uint64_t r;

    if (ctx->key_buf == NULL || ctx->key_len != 4096) {
        ctx->key_len = 4096;
        ctx->key_buf = realloc(ctx->key_buf, ctx->key_len);
    }

    for (int i = 0; i < 4096; ++i) {
        if (i % 8 == 0) {
            r = mt19937_64_rand(mt);
        }
        if (le == 0) {
            ctx->key_buf[i] = r >> ((7 - (i % 8)) * 8);
        } else {
            ctx->key_buf[i] = r >> ((i % 8) * 8);
        }
    }
}

void p2p_set_key_seed(struct p2p_ctx *ctx, const char *seed_str)
{
    uint64_t seed;
    struct mt19937_64_ctx mt;

    seed = strtoull(seed_str, NULL, 10);

    mt19937_64_seed(&mt, seed);
    seed = mt19937_64_rand(&mt);

    mt19937_64_seed(&mt, seed);
    mt19937_64_rand(&mt);

    p2p_pad_key(ctx, &mt, 0);

    ctx->override = 1;

    p2p_log(ctx, 1, "override key: 0x%04X (%d bytes)\n",
            read_uint16_be(ctx->key_buf, 0), ctx->key_len);
}

int p2p_slice_kcp_token(uint8_t *data, uint32_t length, uint8_t *buf)
{
    uint32_t pos;
    uint32_t sliced_len;
    uint32_t cont_len;

    pos = 0;
    sliced_len = 0;
    while (pos < length) {
        if (pos + 28 - 1 >= length) {
            fprintf(stderr, "failed to read kcp packet header\n");
            return ERROR;
        }
        cont_len = read_uint32_le(data, 24);
        if (pos + 28 + cont_len - 1 >= length) {
            fprintf(stderr, "failed to read kcp packet content\n");
            return ERROR;
        }

        memcpy(buf, data, 4);
        memcpy(buf + 4, data + 8, 20 + cont_len);

        pos += 28 + cont_len;
        data += 28 + cont_len;
        buf += 24 + cont_len;
        sliced_len += 4;
    }

    return length - sliced_len;
}

void p2p_realloc_buf(struct p2p_ctx *ctx, size_t size)
{
    if (ctx->buf_len < size) {
        p2p_log(ctx, 1, "extend buf from %d to %d bytes\n", ctx->buf_len, size);
        ctx->buf_len = size;
        ctx->buf = realloc(ctx->buf, ctx->buf_len);
    }
}

int p2p_null_kcp_output(const char *buf, int len, ikcpcb *kcp, void *user)
{
    return len;
}

int p2p_prepare_cur(struct p2p_ctx *ctx)
{
    if (ctx->cur != NULL) {
        return SUCCESS;
    }

    struct pcap_udp4_packet *pkt;
    uint32_t conv;
    int input_len;

    while (1) {
        pkt = pcap_read_udp4_packet(ctx->pfile);
        if (pkt == NULL) {
            p2p_log(ctx, 1, "assume reaching EOF, quit\n");
            return EAGAIN;
        }
        p2p_log(ctx, 1, "captured udp4 packet: %d -> %d (%d bytes)\n",
                pkt->src_port, pkt->dst_port, pkt->length);
        if (pkt->src_port == 22101 || pkt->src_port == 22102 ||
            pkt->dst_port == 22101 || pkt->dst_port == 22102) {
            if (pkt->length > 20) {
                break;
            } else {
                p2p_log(ctx, 1, "packet too small, maybe it is handshake\n");
            }
        }
        p2p_log(ctx, 1, "skip it\n");
        pcap_free_udp4_packet(pkt);
    }

    conv = read_uint32_le(pkt->data, 0);
    p2p_log(ctx, 1, "conv id: %d\n", conv);
    if (ctx->conv != conv) {
        p2p_log(ctx, 1, "it is a new conv (old is %d), restart\n", ctx->conv);
        p2p_clear(ctx);
        p2p_init(ctx);
        ctx->conv = conv;
    }

    if (pkt->src_port == 22101 || pkt->src_port == 22102) {
        if (ctx->server == NULL) {
            p2p_log(ctx, 1, "create new server object\n");
            ctx->server = ikcp_create(conv, NULL);
            ikcp_setoutput(ctx->server, p2p_null_kcp_output);
            ikcp_wndsize(ctx->server, 1024, 1024);
        }
        p2p_log(ctx, 1, "cur set to server\n");
        ctx->cur = ctx->server;
    } else {
        if (ctx->client == NULL) {
            p2p_log(ctx, 1, "create new client object\n");
            ctx->client = ikcp_create(conv, NULL);
            ikcp_setoutput(ctx->client, p2p_null_kcp_output);
            ikcp_wndsize(ctx->client, 1024, 1024);
        }
        p2p_log(ctx, 1, "cur set to client\n");
        ctx->cur = ctx->client;
    }

    p2p_log(ctx, 2, "kcp+token data (%d bytes):\n", pkt->length);
    p2p_log_raw(ctx, 2, pkt->data, pkt->length);

    p2p_realloc_buf(ctx, pkt->length);

    input_len = p2p_slice_kcp_token(pkt->data, pkt->length, ctx->buf);
    if (input_len < 0) {
        pcap_free_udp4_packet(pkt);
        return ERROR;
    }

    p2p_log(ctx, 2, "kcp data (%d bytes):\n", input_len);
    p2p_log_raw(ctx, 2, ctx->buf, input_len);

    ikcp_input(ctx->cur, (char *)ctx->buf, input_len);
    pcap_free_udp4_packet(pkt);

    ikcp_update(ctx->cur, ctx->time++);

    return SUCCESS;
}

int p2p_prepare_key_buf(struct p2p_ctx *ctx, int recv_len)
{
    if (recv_len < 2) {
        fprintf(stderr, "fail to set initial key: len < 2\n");
        return ERROR;
    }
    if (ctx->override) {
        assert(ctx->key_buf != NULL);
        return SUCCESS;
    }

    uint16_t head;
    struct mt19937_64_ctx mt;
    uint64_t r;
    uint16_t key_head;

    head = read_uint16_be(ctx->buf, 0) ^ 0x4567;
    /* check current key by head */
    if (ctx->key_buf != NULL && ctx->key_len >= 2 &&
        head == read_uint16_be(ctx->key_buf, 0)) {
        return SUCCESS;
    }

    /* guess key */
    for (size_t i = 0; i < sizeof(yskeys) >> 3; ++i) {
        mt19937_64_seed(&mt, yskeys[i]);
        r = mt19937_64_rand(&mt);
        key_head = ((r & 0x00ff) << 8) | ((r & 0xff00) >> 8);
        if (key_head == head) {
            mt19937_64_seed(&mt, yskeys[i]);
            p2p_pad_key(ctx, &mt, 1);
            p2p_log(ctx, 1, "set key: 0x%04X (%d bytes)\n", key_head,
                    ctx->key_len);
            return SUCCESS;
        }
    }

    fprintf(stderr, "fail to set initial key: unknown key 0x%04X\n", head);
    return ERROR;
}

int p2p_decrypt_packet(struct p2p_ctx *ctx, uint8_t *proto_buf,
                       uint16_t *packet_id)
{
    int retcode;
    int recv_len;
    int slice_start;
    int slice_end;

    while (1) {
        if ((retcode = p2p_prepare_cur(ctx)) < 0) {
            return retcode;
        }

        recv_len = ikcp_peeksize(ctx->cur);
        p2p_log(ctx, 1, "peeksize: %d\n", recv_len);
        if (recv_len < 0) {
            p2p_log(ctx, 1, "recv nothing: %d\n", recv_len);
            ctx->cur = NULL;
        } else {
            break;
        }
    }

    p2p_realloc_buf(ctx, recv_len);
    recv_len = ikcp_recv(ctx->cur, (char *)ctx->buf, ctx->buf_len);

    p2p_log(ctx, 2, "recv data (%d bytes):\n", recv_len);
    p2p_log_raw(ctx, 2, ctx->buf, recv_len);

    if ((retcode = p2p_prepare_key_buf(ctx, recv_len)) < 0) {
        return retcode;
    }
    for (int i = 0; i < recv_len; ++i) {
        ctx->buf[i] ^= ctx->key_buf[i % ctx->key_len];
    }

    p2p_log(ctx, 2, "decrypted data (%d bytes):\n", recv_len);
    p2p_log_raw(ctx, 2, ctx->buf, recv_len);

    *packet_id = read_uint16_be(ctx->buf, 2);
    p2p_log(ctx, 0, "packet id: %d\n", *packet_id);

    if (6 >= recv_len) {
        fprintf(stderr, "fail to read slice start\n");
        return ERROR;
    }
    slice_start = 10 + ctx->buf[5] + ctx->buf[6]; /* maybe */
    slice_end = recv_len - 2;
    if (slice_start > slice_end) {
        fprintf(stderr, "fail to slice [%d, %d)\n", slice_start, slice_end);
        return ERROR;
    }

    memcpy(proto_buf, ctx->buf + slice_start, slice_end - slice_start);

    p2p_log(ctx, 2, "slice [%d, %d)\n", slice_start, slice_end);
    p2p_log(ctx, 0, "protobuf data (%d bytes):\n", slice_end - slice_start);
    p2p_log_raw(ctx, 0, proto_buf, slice_end - slice_start);

    return slice_end - slice_start;
}

void p2p_set_logger(struct p2p_ctx *ctx, FILE *logger, int verbose)
{
    ctx->logger = logger;
    ctx->verbose = verbose;
}
