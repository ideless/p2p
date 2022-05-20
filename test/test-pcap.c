#include "pcap.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_data(uint8_t *data, size_t length)
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

void test_packet(uint8_t *data, uint32_t length, int print, int only)
{
    struct pcap_file *pfile = pcap_open(data, length);
    if (pfile == NULL) {
        return;
    }

    /* print global header */
    printf("magic number: 0x%x\n", pfile->header->magic_number);
    printf("version: %d.%d\n", pfile->header->major_version,
           pfile->header->minor_version);
    printf("gmt offset: %d\n", pfile->header->gmt_offset);
    printf("timestamp accuracy: %d\n", pfile->header->timestamp_accuracy);
    printf("snapshot length: %d\n", pfile->header->snapshot_length);
    printf("link layer type: %d\n", pfile->header->link_type);

    /* iterate over packets */
    struct pcap_packet *pkt;
    int cnt = 0;

    while ((only < 0 || cnt < only) &&
           (pkt = pcap_read_packet(pfile)) != NULL) {
        printf("\n");
        printf("timestamp seconds: %d\n", pkt->header->timestamp_seconds);
        printf("timestamp microseconds: %d\n",
               pkt->header->timestamp_microseconds);
        printf("captured length: %d\n", pkt->header->captured_length);
        printf("original length: %d\n", pkt->header->original_length);
        if (print)
            print_data(pkt->data, pkt->header->captured_length);
        pcap_free_packet(pkt);
        cnt++;
    }

    pcap_close(pfile);
}

char *ip_str(uint32_t ip, char buf[])
{
    sprintf(buf, "%d.%d.%d.%d", (ip & 0xff000000) >> 24,
            (ip & 0x00ff0000) >> 16, (ip & 0x0000ff00) >> 8, (ip & 0x000000ff));
    return buf;
}

void test_udp4_packet(uint8_t *data, uint32_t length, int print, int only)
{
    struct pcap_file *pfile = pcap_open(data, length);
    if (pfile == NULL) {
        return;
    }

    /* print global header */
    printf("magic number: 0x%x\n", pfile->header->magic_number);
    printf("version: %d.%d\n", pfile->header->major_version,
           pfile->header->minor_version);
    printf("gmt offset: %d\n", pfile->header->gmt_offset);
    printf("timestamp accuracy: %d\n", pfile->header->timestamp_accuracy);
    printf("snapshot length: %d\n", pfile->header->snapshot_length);
    printf("link layer type: %d\n", pfile->header->link_type);

    /* iterate over packets */
    struct pcap_udp4_packet *pkt;
    int cnt = 0;
    while ((only < 0 || cnt < only) &&
           (pkt = pcap_read_udp4_packet(pfile)) != NULL) {
        if (pkt->src_port != 22101 && pkt->src_port != 22102 &&
            pkt->dst_port != 22101 && pkt->dst_port != 22102) {
            continue;
        }
        printf("\n");
        printf("timestamp seconds: %d\n", pkt->header->timestamp_seconds);
        printf("timestamp microseconds: %d\n",
               pkt->header->timestamp_microseconds);
        printf("captured length: %d\n", pkt->header->captured_length);
        printf("original length: %d\n", pkt->header->original_length);
        char buf[16];
        printf("source: %s:%d\n", ip_str(pkt->src_ip, buf), pkt->src_port);
        printf("destination: %s:%d\n", ip_str(pkt->dst_ip, buf), pkt->dst_port);
        printf("data length: %d\n", pkt->length);
        if (print)
            print_data(pkt->data, pkt->length);
        pcap_free_udp4_packet(pkt);
        cnt++;
    }

    pcap_close(pfile);
}

int main()
{
    char filename[] = "../test/example.pcap";
    FILE *file;
    uint32_t length;
    uint8_t *data;

    file = fopen(filename, "rb");
    if (file == NULL) {
        fprintf(stderr, "fail to open file %s: %s", filename, strerror(errno));
        return 0;
    }

    fseek(file, 0L, SEEK_END);
    length = ftell(file);
    fseek(file, 0L, SEEK_SET);
    printf("file size: %d\n", length);

    data = malloc(length);
    if (fread(data, length, 1, file) != 1) {
        fprintf(stderr, "fail to read file");
        free(data);
        fclose(file);
        return 0;
    }
    test_udp4_packet(data, length, 1, 5);
    free(data);

    fclose(file);
}
