#include "mt19937-64.h"
#include <stdio.h>

int main()
{
    uint64_t seed = 123456;
    struct mt19937_64_ctx ctx;

    mt19937_64_seed(&ctx, seed);
    for (int i = 0; i < 5; ++i) {
        printf("%" PRIu64 "\n", mt19937_64_rand(&ctx));
    }
}
