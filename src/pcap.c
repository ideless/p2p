#include "pcap.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

uint8_t *pcap_read_file(struct pcap_file *pfile, uint32_t length)
{
    if (pfile->pos + length - 1 >= pfile->length) {
        return NULL;
    } else {
        pfile->pos += length;
        return pfile->data + (pfile->pos - length);
    }
}

struct pcap_global_header *pcap_read_global_header(struct pcap_file *pfile)
{
    struct pcap_global_header *pgh;
    uint8_t *buf;

    if ((buf = pcap_read_file(pfile, 24)) == NULL) {
        fprintf(stderr, "EOF reached before global header is read\n");
        return NULL;
    }

    pgh = malloc(sizeof *pgh);

    pgh->magic_number = read_uint32_be(buf, 0);
    if (pgh->magic_number == 0xa1b2c3d4) {
        pgh->major_version = read_uint16_be(buf, 4);
        pgh->minor_version = read_uint16_be(buf, 6);
        pgh->gmt_offset = read_uint32_be(buf, 8);
        pgh->timestamp_accuracy = read_uint32_be(buf, 12);
        pgh->snapshot_length = read_uint32_be(buf, 16);
        pgh->link_type = read_uint32_be(buf, 20);
    } else if (pgh->magic_number == 0xd4c3b2a1) {
        pgh->major_version = read_uint16_le(buf, 4);
        pgh->minor_version = read_uint16_le(buf, 6);
        pgh->gmt_offset = read_uint32_le(buf, 8);
        pgh->timestamp_accuracy = read_uint32_le(buf, 12);
        pgh->snapshot_length = read_uint32_le(buf, 16);
        pgh->link_type = read_uint32_le(buf, 20);
    } else {
        fprintf(stderr, "unknown magic number: 0x%x\n", pgh->magic_number);
        free(pgh);
        return NULL;
    }

    if (pgh->major_version != 2 || pgh->minor_version != 4) {
        fprintf(stderr, "unsupported pcap version %d.%d (supported: 2.4)\n",
                pgh->major_version, pgh->minor_version);
        free(pgh);
        return NULL;
    }

    return pgh;
}

struct pcap_file *pcap_open(uint8_t *data, uint32_t length)
{
    struct pcap_file *pfile;

    pfile = malloc(sizeof *pfile);

    pfile->data = data;
    pfile->length = length;
    pfile->pos = 0;

    pfile->header = pcap_read_global_header(pfile);
    if (pfile->header == NULL) {
        pcap_close(pfile);
        return NULL;
    }

    return pfile;
}

void pcap_close(struct pcap_file *pfile)
{
    free(pfile->header);
    free(pfile);
}

struct pcap_packet_header *pcap_read_packet_header(struct pcap_file *pfile)
{
    struct pcap_packet_header *pph;
    uint8_t *buf;

    if ((buf = pcap_read_file(pfile, 16)) == NULL) {
        /* assume EOF reached */
        return NULL;
    }

    pph = malloc(sizeof *pph);

    if (pfile->header->magic_number == 0xa1b2c3d4) {
        pph->timestamp_seconds = read_uint32_be(buf, 0);
        pph->timestamp_microseconds = read_uint32_be(buf, 4);
        pph->captured_length = read_uint32_be(buf, 8);
        pph->original_length = read_uint32_be(buf, 12);
    } else {
        pph->timestamp_seconds = read_uint32_le(buf, 0);
        pph->timestamp_microseconds = read_uint32_le(buf, 4);
        pph->captured_length = read_uint32_le(buf, 8);
        pph->original_length = read_uint32_le(buf, 12);
    }

    return pph;
}

struct pcap_packet *pcap_read_packet(struct pcap_file *pfile)
{
    struct pcap_packet *pkt;

    pkt = malloc(sizeof *pkt);

    pkt->header = pcap_read_packet_header(pfile);
    if (pkt->header == NULL) {
        free(pkt);
        return NULL;
    }

    if ((pkt->data = pcap_read_file(pfile, pkt->header->captured_length)) ==
        NULL) {
        fprintf(stderr, "EOF reached before packet body is read\n");
        pcap_free_packet(pkt);
        return NULL;
    }

    return pkt;
}

void pcap_free_packet(struct pcap_packet *pkt)
{
    free(pkt->header);
    free(pkt);
}

/*
struct ether_header {
    uint8_t dst_mac[6]; // 0
    uint8_t src_mac[6]; // 6
    uint16_t type;      // 12
};

struct ipv4_header {
    uint8_t version;         // 14
    uint8_t service;         // 15
    uint16_t total_length;   // 16
    uint16_t identificaiton; // 18
    uint8_t flags;           // 20
    uint8_t fragment_offset; // 21
    uint8_t time_to_live;    // 22
    uint8_t protocol;        // 23
    uint16_t checksum;       // 24
    uint32_t src_ip;         // 26
    uint32_t dst_ip;         // 30
};

struct udp_header {
    uint16_t src_port; // 34
    uint16_t dst_port; // 36
    uint16_t length;   // 38
    uint16_t checksum; // 40
};

char *ip2str(uint32_t ip, char buf[])
{
    sprintf(buf, "%d.%d.%d.%d", (ip & 0xff000000) >> 24,
            (ip & 0x00ff0000) >> 16, (ip & 0x0000ff00) >> 8, (ip & 0x000000ff));
    return buf;
}

void print_raw(uint8_t *data, size_t length)
{
    for (size_t i = 0; i < length; ++i) {
        if (i % 16 == 4 || i % 16 == 8 || i % 16 == 12) {
            printf(" ");
        } else if (i && i % 16 == 0) {
            printf("\n");
        }
        printf("%02X ", data[i]);
    }
    printf("\n");
}
*/

struct pcap_udp4_packet *pcap_read_udp4_packet(struct pcap_file *pfile)
{
    if (pfile->header->link_type != 1) {
        /* Not ethernet */
        return NULL;
    }

    struct pcap_udp4_packet *pkt;
    uint8_t *buf;
    uint16_t ipv4_len, udp_len;
    // char ip_buf[16];

    pkt = malloc(sizeof *pkt);

    while (1) {
        /* header */
        pkt->header = pcap_read_packet_header(pfile);
        if (pkt->header == NULL) {
            /* assume EOF reached, quit safely */
            free(pkt);
            return NULL;
        }

        // printf("\n");
        // printf("timestamp seconds: %d\n", pkt->header->timestamp_seconds);
        // printf("timestamp microseconds: %d\n",
        //        pkt->header->timestamp_microseconds);
        // printf("captured length: %d\n", pkt->header->captured_length);
        // printf("original length: %d\n", pkt->header->original_length);

        if (pkt->header->captured_length < 42) {
            /* Not a udp4 packet, skip it */
            pfile->pos += pkt->header->captured_length;
            free(pkt->header);
            // printf("INFO captured length < 42, not a udp4 packet, skip
            // it\n");
            continue;
        }

        if ((buf = pcap_read_file(pfile, 42)) == NULL) {
            fprintf(stderr, "unexpected EOF\n");
            free(pkt->header);
            free(pkt);
            return NULL;
        }

        if (read_uint16_be(buf, 12) != 0x0800 || buf[23] != 17) {
            /* Not a udp4 packet, skip it */
            pfile->pos += pkt->header->captured_length - 42;
            free(pkt->header);
            // printf("INFO not a ipv4 and udp packet\n");
            continue;
        }

        // struct ether_header eth_hdr;
        // struct ipv4_header ip4_hdr;
        // struct udp_header udp_hdr;

        // memcpy(eth_hdr.dst_mac, buf, 6);
        // memcpy(eth_hdr.src_mac, buf + 6, 6);
        // eth_hdr.type = read_uint16_be(buf, 12);

        // ip4_hdr.version = buf[14];
        // ip4_hdr.service = buf[15];
        // ip4_hdr.total_length = read_uint16_be(buf, 16);
        // ip4_hdr.identificaiton = read_uint16_be(buf, 18);
        // ip4_hdr.flags = buf[20];
        // ip4_hdr.fragment_offset = buf[21];
        // ip4_hdr.time_to_live = buf[22];
        // ip4_hdr.protocol = buf[23];
        // ip4_hdr.checksum = read_uint16_be(buf, 24);
        // ip4_hdr.src_ip = read_uint32_be(buf, 26);
        // ip4_hdr.dst_ip = read_uint32_be(buf, 30);

        // udp_hdr.src_port = read_uint16_be(buf, 34);
        // udp_hdr.dst_port = read_uint16_be(buf, 36);
        // udp_hdr.length = read_uint16_be(buf, 38);
        // udp_hdr.checksum = read_uint16_be(buf, 40);

        // printf("Ether header\n");
        // printf("    dst_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
        //        eth_hdr.dst_mac[0], eth_hdr.dst_mac[1], eth_hdr.dst_mac[2],
        //        eth_hdr.dst_mac[3], eth_hdr.dst_mac[4], eth_hdr.dst_mac[5]);
        // printf("    src_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
        //        eth_hdr.src_mac[0], eth_hdr.src_mac[1], eth_hdr.src_mac[2],
        //        eth_hdr.src_mac[3], eth_hdr.src_mac[4], eth_hdr.src_mac[5]);
        // printf("    type   : %04x\n", eth_hdr.type);

        // printf("IPv4 header\n");
        // printf("    version: %d\n", ip4_hdr.version);
        // printf("    service: %d\n", ip4_hdr.service);
        // printf("    length : %d\n", ip4_hdr.total_length);
        // printf("    id     : %d\n", ip4_hdr.identificaiton);
        // printf("    flags  : %d\n", ip4_hdr.flags);
        // printf("    frg_off: %d\n", ip4_hdr.fragment_offset);
        // printf("    ttl    : %d\n", ip4_hdr.time_to_live);
        // printf("    protoc : %d\n", ip4_hdr.protocol);
        // printf("    chk_sum: %d\n", ip4_hdr.checksum);
        // printf("    src_ip : %s\n", ip2str(ip4_hdr.src_ip, ip_buf));
        // printf("    dst_ip : %s\n", ip2str(ip4_hdr.dst_ip, ip_buf));

        // printf("UDP header\n");
        // printf("    srcport: %d\n", udp_hdr.src_port);
        // printf("    dstport: %d\n", udp_hdr.dst_port);
        // printf("    length : %d\n", udp_hdr.length);
        // printf("    chk_sum: %d\n", udp_hdr.checksum);

        /* length check */
        ipv4_len = read_uint16_be(buf, 16);
        udp_len = read_uint16_be(buf, 38);
        /* I don't know why but sometimes data is padded */
        assert(pkt->header->captured_length >= ipv4_len + 14);
        assert(ipv4_len == udp_len + 20);
        assert(udp_len >= 8);

        /* ip, port & length */
        pkt->src_ip = read_uint32_be(buf, 26);
        pkt->dst_ip = read_uint32_be(buf, 30);
        pkt->src_port = read_uint16_be(buf, 34);
        pkt->dst_port = read_uint16_be(buf, 36);
        pkt->length = udp_len - 8;

        /* data */
        if ((pkt->data = pcap_read_file(pfile, pkt->length)) == NULL) {
            fprintf(stderr, "EOF reached before packet body is read\n");
            pcap_free_udp4_packet(pkt);
            return NULL;
        }

        /* I don't know why but sometimes data is padded */
        pfile->pos += pkt->header->captured_length - (ipv4_len + 14);

        // if (ip4_hdr.total_length + 14 != pkt->header->captured_length ||
        //     udp_hdr.length + 34 != pkt->header->captured_length) {
        //     printf("ERROR length check failed: %d\n ",
        //            (int)pkt->header->captured_length - 14 -
        //                ip4_hdr.total_length);
        //     // print_raw(pkt->data, pkt->length);
        // }

        return pkt;
    }
}

void pcap_free_udp4_packet(struct pcap_udp4_packet *pkt)
{
    free(pkt->header);
    free(pkt);
}
