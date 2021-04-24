#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdalign.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#ifdef __unix__
#include <sys/mman.h>
#else
#include <windows.h>
#define MAP_FAILED NULL
#endif // __unix__


typedef struct Header {
    size_t size;
    bool free : 1;
    bool has_prev : 1;
    bool has_next : 1;
} Header;

// Size field is not necessary in used blocks.
typedef struct Footer {
    size_t size;
    bool free : 1;
} Footer;

typedef struct free_list {
    struct free_list *next;
    struct free_list *prev;
} free_list;

typedef struct node {
    free_list *next;
    free_list *prev;
    struct node *left, *right;
    int diff;
    size_t size;
} node;


/*	Allocate 'size' bytes of memory. On success the function returns a pointer to
	the start of the allocated region. On failure NULL is returned. */
extern void *mem_alloc(size_t size);

/*	Release the region of memory pointed to by 'ptr'. */
extern void mem_free(void *ptr);

/*	Reallocate the region of memory pointed to by 'ptr' based on the 'size'. */
extern void *mem_realloc(void *ptr, size_t size);

/*	Show the region of memory pointed to by 'ptr'. */
extern void mem_show(void *ptr);

/*	Unmap the region of memory pointed to by 'ptr'. */
extern int _free(void *ptr, size_t size);
