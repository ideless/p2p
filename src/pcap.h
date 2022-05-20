/**
 * A pcap 2.4 parser
 *
 * Pcap format:
 * - https://wiki.wireshark.org/Development/LibpcapFileFormat
 * - https://www.slideshare.net/ShravanKumarCEHOSCP/pcap-headers-description
 * Ethertypes:
 * - https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
 */

#ifndef PCAP_H
#define PCAP_H

#include <inttypes.h>
#include <stdio.h>

#define swap_uint32(x)                                                         \
    ((((x)&0x000000ff) << 24) | (((x)&0x0000ff00) << 8) |                      \
     (((x)&0x00ff0000) >> 8) | (((x)&0xff000000) >> 24))

#define swap_uint16(x) ((((x)&0x00ff) << 8) | (((x)&0xff00) >> 8))

#define read_uint16_be(b, o) ((((b)[o]) << 8) | ((b)[o + 1]))
#define read_uint16_le(b, o) ((((b)[o + 1]) << 8) | ((b)[o]))
#define read_uint32_be(b, o)                                                   \
    ((((b)[o]) << 24) | (((b)[o + 1]) << 16) | (((b)[o + 2]) << 8) |           \
     ((b)[o + 3]))
#define read_uint32_le(b, o)                                                   \
    ((((b)[o + 3]) << 24) | (((b)[o + 2]) << 16) | (((b)[o + 1]) << 8) |       \
     ((b)[o]))

struct pcap_global_header {
    uint32_t magic_number;
    uint16_t major_version;
    uint16_t minor_version;
    int32_t gmt_offset;
    uint32_t timestamp_accuracy;
    uint32_t snapshot_length;
    uint32_t link_type;
};

struct pcap_packet_header {
    uint32_t timestamp_seconds;
    uint32_t timestamp_microseconds;
    uint32_t captured_length;
    uint32_t original_length;
};

struct pcap_file {
    uint8_t *data;
    uint32_t length;
    uint32_t pos;
    struct pcap_global_header *header;
};

struct pcap_packet {
    struct pcap_packet_header *header;
    uint8_t *data;
};

struct pcap_udp4_packet {
    struct pcap_packet_header *header;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint8_t *data;
};

/**
 * @brief open a pcap stream from data buffer
 * @return stream pointer, or NULL if failed
 */
struct pcap_file *pcap_open(uint8_t *, uint32_t);

/**
 * @brief close stream
 */
void pcap_close(struct pcap_file *);

/**
 * @brief read a packet
 * @return packet pointer, or NULL if failed
 */
struct pcap_packet *pcap_read_packet(struct pcap_file *);

/**
 * @brief free a packet
 */
void pcap_free_packet(struct pcap_packet *);

/**
 * @brief read a ipv4 udp packet, all headers will be stripped
 * @return packet pointer, or NULL if failed
 */
struct pcap_udp4_packet *pcap_read_udp4_packet(struct pcap_file *);

/**
 * @brief free a packet
 */
void pcap_free_udp4_packet(struct pcap_udp4_packet *);

#endif
