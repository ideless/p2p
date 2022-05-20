/**
 * Yuanshen Pcap To Protobuf parser
 */

#ifndef P2P_H
#define P2P_H

#include "kcp/ikcp.h"
#include "pcap.h"

struct p2p_ctx {
    struct pcap_file *pfile;
    uint8_t *key_buf;
    uint16_t key_len; /* typically 4096 */
    uint8_t override; /* whether an override key is set */
    uint32_t conv;    /* kcp conv id */
    ikcpcb *server;
    ikcpcb *client;
    uint32_t time; /* fake current time */
    ikcpcb *cur;   /* point to server or client if receiving, or NULL if not */
    uint8_t *buf;  /* buffer chunk */
    uint32_t buf_len; /* len of buffer */
    FILE *logger;
    uint8_t verbose;
};

/**
 * @return p2p context pointer, or NULL if failed
 */
struct p2p_ctx *p2p_open(uint8_t *, uint32_t);

/**
 * @brief close p2p context object
 */
void p2p_close(struct p2p_ctx *);

/**
 * @brief update key by seed, override initial key only in one kcp conv session
 */
void p2p_set_key_seed(struct p2p_ctx *, const char *);

/**
 * @brief Get next protobuf, along with its packet id
 * @return size of protobuf, or -1 if reached the end, or -2 if failed
 */
int32_t p2p_decrypt_packet(struct p2p_ctx *, uint8_t *, uint16_t *);

#endif
