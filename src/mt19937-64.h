/**
 * Rewrite from
 * https://github.com/mattgallagher/CwlUtils/blob/master/Sources/ReferenceRandomGenerators/mt19937-64.c
 */

#ifndef MT19937_64
#define MT19937_64

#include <inttypes.h>
#include <stddef.h>

struct mt19937_64_ctx {
    uint64_t mt[312];
    size_t mti;
};

void mt19937_64_seed(struct mt19937_64_ctx *, uint64_t);
uint64_t mt19937_64_rand(struct mt19937_64_ctx *);

#endif
