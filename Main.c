#include "mem_alloc.h"

#define SMALL_SIZE_MIN 0
#define SMALL_SIZE_MAX 64
#define LARGE_SIZE_MIN 512
#define LARGE_SIZE_MAX 1000000
#define ITERATION_COUNT 500
#define N 100
#define RAND_RANGE(a, b) ((a) + rand() % ((b) - (a)))
#define RAND_SIZE() \
    ((rand() & 1) \
       ? RAND_RANGE(SMALL_SIZE_MIN, SMALL_SIZE_MAX) \
       : RAND_RANGE(LARGE_SIZE_MIN, LARGE_SIZE_MAX))

/* Saves the rand seed so we can reproduce crashes */
static unsigned int seed;

typedef struct result {
    unsigned long *ptr;
    size_t size;
    unsigned long checksum;
} result;


int main() {
    // result res[N] = {{ .ptr = NULL, .size = 0, .checksum = 0 }};

    // /* I can haz randomness? */
    // seed = (unsigned int)time(NULL);
    // srand(seed);

    // size_t prev = 0;

    // /* malloc some randomly sized blocks */
    // for (int i = 0; i < ITERATION_COUNT; ++i) {
    //     int j = rand() % N;
    //     if (res[j].ptr == NULL) {
    //         size_t sz = RAND_SIZE();
    //         res[j].ptr = mem_alloc(sz);
    //         if (res[j].ptr != NULL) {
    //             mem_show(res[j].ptr);
    //             res[j].size = sz;
    //             res[j].ptr[0] = prev;
    //             res[j].checksum = (size_t)res[j].ptr[0] + sz;
    //             prev += res[j].size;
    //         }
    //     } else {
    //         if (res[j].checksum != (res[j].ptr[0] + res[j].size)) {
    //             printf("Checksum failed");
    //             return -1;
    //         }

    //         if (rand() & 1) {
    //             size_t sz = RAND_SIZE();
    //             void *x = mem_realloc(res[j].ptr, sz);

    //             if (sz != 0 || x != NULL) {
    //                 res[j].ptr = x;
    //                 res[j].ptr[0] = prev;
    //                 res[j].size = sz;
    //                 res[j].checksum = (size_t)res[j].ptr[0] + sz;
    //                 prev += res[j].size;
    //             } else {
    //                 res[j].ptr = NULL;
    //                 res[j].size = 0;
    //                 res[j].checksum = 0u;
    //             }
    //         } else {
    //             mem_free(res[j].ptr);
    //             res[j].ptr = NULL;
    //             res[j].size = 0;
    //             res[j].checksum = 0u;
    //         }

    //         mem_show(res[j].ptr);
    //     }
    // }

    // /* Clean up our mess */
    // for (int i = 0; i < N; ++i) {
    //     if (res[i].ptr && res[i].checksum != (res[i].ptr[0] + res[i].size)) {
    //         printf("Checksum failed");
    //         return -1;
    //     }
    //     _free(res[i].ptr, (size_t) res[i].size);
    // }

    /* Stuff to store our checks */
    char *ptrs[ITERATION_COUNT];
    int sizes[ITERATION_COUNT];
    char chrs[ITERATION_COUNT];

    unsigned long total = 0u;
    unsigned ctrSum = 0u;
    unsigned testSum = 0u;

    /* I can haz randomness? */
    seed = (unsigned int)time(NULL);
    srand(seed);

    /* malloc some randomly sized blocks */
    for (int i = 0; i < ITERATION_COUNT; ++i) {
        size_t sz = RAND_SIZE();
        sizes[i] = 0;
        ptrs[i] = mem_alloc(sz);
        if (ptrs[i] != NULL) {
            total += sz;
            mem_show(ptrs[i]);
            sizes[i] = sz;
            char rchr = (char)RAND_RANGE(0, 256);
            chrs[i] = rchr;
            ctrSum += rchr;
            for (size_t j = 0; j < sz; ++j) {
                ptrs[i][j] = chrs[i];
            }
        }
    }

    printf("%s - %7d\n\n", "Total", total);

    /* Check on data modification */
    for (int i = 0; i < ITERATION_COUNT; ++i) {
        testSum += chrs[i];
    }

    // if (testSum != ctrSum) {
    //     printf("ERROR Data modification");
    //     return -1;
    // }

    /* free some of the pointers */
    for (int i = 0; i < ITERATION_COUNT / 2; ++i) {
        int index = rand() % ITERATION_COUNT;
        mem_free(ptrs[index]);
        mem_show(ptrs[index]);
        ptrs[index] = NULL;
        sizes[index] = 0;
        chrs[index] = '\0';
    }


    /* realloc some of the pointers */
    for (int i = 0; i < ITERATION_COUNT / 2; ++i) {
        int index = rand() % ITERATION_COUNT;
        size_t sz = RAND_SIZE();
        void *x = mem_realloc(ptrs[index], sz);

        if (sz == 0 || x != NULL) {
            ptrs[index] = x;
            mem_show(ptrs[index]);
            sizes[index] = sz;
            chrs[index] = (char)RAND_RANGE(0, 256);
            for (size_t j = 0; j < sz; ++j) {
                ptrs[index][j] = chrs[index];
            }
        }
    }

    /* Make sure our data is still intact */
    for (int i = 0; i < ITERATION_COUNT; ++i) {
        for (int j = 0; j < sizes[i]; ++j) {
            if (ptrs[i][j] != chrs[i]) {
              return -1;
            }
        }
    }

    /* Clean up our mess */
    for (int i = 0; i < ITERATION_COUNT; ++i) {
        _free(ptrs[i], (size_t) sizes[i]);
        ptrs[i] = NULL;
        sizes[i] = 0;
        chrs[i] = '\0';
    }

    printf("PASS!");
    return 0;
}
