#include "mt19937-64.h"

#define NN 312
#define MM 156
#define MATRIX_A 0xB5026F5AA96619E9ULL
#define UM 0xFFFFFFFF80000000ULL /* Most significant 33 bits */
#define LM 0x7FFFFFFFULL         /* Least significant 31 bits */

void mt19937_64_seed(struct mt19937_64_ctx *ctx, uint64_t seed)
{
    ctx->mt[0] = seed;
    for (ctx->mti = 1; ctx->mti < NN; ctx->mti++) {
        ctx->mt[ctx->mti] =
            (6364136223846793005ULL *
                 (ctx->mt[ctx->mti - 1] ^ (ctx->mt[ctx->mti - 1] >> 62)) +
             ctx->mti);
    }
}

uint64_t mt19937_64_rand(struct mt19937_64_ctx *ctx)
{
    size_t i;
    size_t j;
    unsigned long long result;

    if (ctx->mti >= NN) { /* generate NN words at one time */
        size_t mid = NN / 2;
        unsigned long long stateMid = ctx->mt[mid];
        unsigned long long x;
        unsigned long long y;

        /* NOTE: this "untwist" code is modified from the original to improve
         * performance, as described here:
         * http://www.cocoawithlove.com/blog/2016/05/19/random-numbers.html
         * These modifications are offered for use under the original icense at
         * the top of this file.
         */
        for (i = 0, j = mid; i != mid - 1; i++, j++) {
            x = (ctx->mt[i] & UM) | (ctx->mt[i + 1] & LM);
            ctx->mt[i] =
                ctx->mt[i + mid] ^ (x >> 1) ^ ((ctx->mt[i + 1] & 1) * MATRIX_A);
            y = (ctx->mt[j] & UM) | (ctx->mt[j + 1] & LM);
            ctx->mt[j] =
                ctx->mt[j - mid] ^ (y >> 1) ^ ((ctx->mt[j + 1] & 1) * MATRIX_A);
        }
        x = (ctx->mt[mid - 1] & UM) | (stateMid & LM);
        ctx->mt[mid - 1] =
            ctx->mt[NN - 1] ^ (x >> 1) ^ ((stateMid & 1) * MATRIX_A);
        y = (ctx->mt[NN - 1] & UM) | (ctx->mt[0] & LM);
        ctx->mt[NN - 1] =
            ctx->mt[mid - 1] ^ (y >> 1) ^ ((ctx->mt[0] & 1) * MATRIX_A);

        ctx->mti = 0;
    }

    result = ctx->mt[ctx->mti];
    ctx->mti = ctx->mti + 1;

    result ^= (result >> 29) & 0x5555555555555555ULL;
    result ^= (result << 17) & 0x71D67FFFEDA60000ULL;
    result ^= (result << 37) & 0xFFF7EEE000000000ULL;
    result ^= (result >> 43);

    return result;
}
