#include "p2p.h"
#include <errno.h>
#include <string.h>

int main()
{
    char filename[] = "../test/example.pcap";
    FILE *file;
    struct p2p_ctx *ctx;
    uint8_t *data;
    uint32_t length;
    uint8_t *proto_buf;
    uint16_t packet_id;
    int packet_size;
    char *init_seeds[] = {"5030560303351918544"};
    char key_seed[] = "14999200326815492164";

    file = fopen(filename, "rb");
    if (file == NULL) {
        fprintf(stderr, "failed to open file %s: %s", filename,
                strerror(errno));
        return 0;
    }

    fseek(file, 0L, SEEK_END);
    length = ftell(file);
    fseek(file, 0L, SEEK_SET);

    data = malloc(length);
    if (fread(data, length, 1, file) != 1) {
        fprintf(stderr, "fail to read file");
        free(data);
        fclose(file);
        return 0;
    }

    ctx = p2p_open(data, length);

    ctx->logger = stdout;
    ctx->verbose = 5;

    //    p2p_set_init_seeds(ctx, init_seeds, 1);

    proto_buf = malloc(length);
    while ((packet_size = p2p_decrypt_packet(ctx, proto_buf, &packet_id)) >=
           0) {
        if (packet_id == 131) {
            p2p_set_key_seed(ctx, key_seed);
        }
    }
    free(proto_buf);

    p2p_close(ctx);

    fclose(file);
    free(data);
}
