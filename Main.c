#include "mem_alloc.h"

#define SMALL_SIZE_MIN 16
#define SMALL_SIZE_MAX 64
#define LARGE_SIZE_MIN 512
#define LARGE_SIZE_MAX 1000000
#define ITERATION_COUNT 200
#define N 100
#define RAND_RANGE(a, b) ((a) + rand() % ((b) - (a)))
#define RAND_SIZE() \
    ((rand() & 1) \
       ? RAND_RANGE(SMALL_SIZE_MIN, SMALL_SIZE_MAX) \
       : RAND_RANGE(LARGE_SIZE_MIN, LARGE_SIZE_MAX))

/* Saves the rand seed so we can reproduce crashes */
static unsigned int seed;

typedef struct result {
    unsigned char *ptr;
    size_t size;
    unsigned long checksum;
} result;

unsigned long checksum(unsigned char *ptr, size_t sz) {
    unsigned long chk = 0u;
    while (--sz != 0)
        chk -= *ptr++;
    return chk;
}

void fill(unsigned char *ptr, size_t sz) {
    size_t sz_ = sz;
    while (sz >= sizeof(size_t)) {
        ptr += sizeof(size_t);
        sz -= sizeof(size_t);
        *ptr = sz_;
    }
}


int main() {
    result res[N] = {{ .ptr = NULL, .size = 0, .checksum = 0 }};

    /* I can haz randomness? */
    seed = (unsigned int)time(NULL);
    srand(seed);

    /* malloc some randomly sized blocks */
    for (int i = 0; i < ITERATION_COUNT; ++i) {
        int j = rand() % N;
        if (res[j].ptr == NULL) {
            size_t sz = RAND_SIZE();
            res[j].ptr = mem_alloc(sz);
            if (res[j].ptr != NULL) {
                mem_show(res[j].ptr);
                res[j].size = sz;
                fill(res[j].ptr, sz);
                res[j].checksum = checksum(res[j].ptr, sz);
            }
        } else {
            if (res[j].ptr && res[j].checksum != checksum(res[j].ptr, res[j].size)) {
                printf("Checksum failed - 1");
                return -1;
            }

            if (rand() & 1) {
                size_t sz = RAND_SIZE();
                void *x = mem_realloc(res[j].ptr, sz);

                if (x != NULL) {
                    res[j].ptr = x;
                    res[j].size = sz;
                    fill(res[j].ptr, sz);
                    res[j].checksum = checksum(res[j].ptr, sz);
                }
            } else {
                mem_free(res[j].ptr);
                res[j].ptr = NULL;
                res[j].size = 0u;
                res[j].checksum = 0u;
            }

            mem_show(res[j].ptr);
        }
    }

    /* Clean up our mess */
    for (int i = 0; i < N; ++i) {
        if (res[i].ptr && res[i].checksum != checksum(res[i].ptr, res[i].size)) {
            printf("Checksum failed - 2");
            return -1;
        }
        _free(res[i].ptr, (size_t) res[i].size);
    }

    printf("PASS!");
    return 0;
}
