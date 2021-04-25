#include "mem_alloc.h"

void *last_address = NULL;

node *avl_root = NULL;
free_list *free_list_start = NULL;

#define ALIGN(x, align) (((x) + (align) - 1) & -(align))
#define MAX(x, y) ((x > y) ? (x) : (y))
#define PAGE_SIZE 4096
#define PAGES(size) (size / PAGE_SIZE + (size % PAGE_SIZE ? 1 : 0))

// Meta sizes.
#define HEADER_SIZE ALIGN(sizeof(Header), alignof(max_align_t))
#define FOOTER_SIZE ALIGN(sizeof(Footer), alignof(max_align_t))
#define NODE_SIZE ALIGN(sizeof(node), alignof(max_align_t))
// #define LIST_SIZE ALIGN(sizeof(free_list), alignof(max_align_t))
#define META_SIZE ALIGN(sizeof(Header) + sizeof(Footer), alignof(max_align_t))

// Get pointer to the payload (passing the pointer to the header).
static inline void *add_offset(void *ptr) {
    return (void *)((char *)ptr + HEADER_SIZE);
}

// Get pointer to the header (passing pointer to the payload).
static inline void *remove_offset(void *ptr) {
    return (void *)((char *)ptr - HEADER_SIZE);
}

static inline void *getFooter(void *header_ptr) {
    return (void *)((char *)add_offset(header_ptr) + ((Header *)header_ptr)->size);
}

static inline void setFree(void *ptr, bool free) {
    ((Header *)ptr)->free = free;
    Footer *footer = (Footer *)getFooter(ptr);
    footer->free = free;
}

// Set size in the header.
static inline void setSizeHeader(void *ptr, size_t size) {
    ((Header *)ptr)->size = size;
}

// Set size in the header.
static inline void setSizeFooter(void *ptr, size_t size) {
    ((Footer *)getFooter(ptr))->size = size;
}

// Get size of the free list item.
static inline size_t getSize(void *ptr) {
    return ((Header *)remove_offset(ptr))->size;
}

static inline int max(int a, int b) {
    return a > b ? a : b;
}

static inline int min(int a, int b) {
    return a < b ? a : b;
}

static inline void fix_diffs_right(int *ap, int *bp) {
    int a = *ap, b = *bp, k = (b > 0) * b;
    *ap = k + (a - b) + 1;
    *bp = max(b, k + a + 1) + 1;
}

static inline void fix_diffs_left(int *ap, int *bp) {
    int a = *ap, b = *bp, k = (b < 0) * b;
    *ap = k + (a - b) - 1;
    *bp = min(b, k + a - 1) - 1;
}

static inline void rotate_right(node **rp) {
    node *a = *rp, *b = a->left;
    a->left = b->right;
    b->right = a;
    fix_diffs_right(&a->diff, &b->diff);
    *rp = b;
}

static inline void rotate_left(node **rp) {
    node *a = *rp, *b = a->right;
    a->right = b->left;
    b->left = a;
    fix_diffs_left(&a->diff, &b->diff);
    *rp = b;
}

static inline int balance(node **rp) {
    node *a = *rp;
    if (a->diff == 2) {
        if (a->right->diff == -1)
            rotate_right(&a->right);
        rotate_left(rp);
        return 1;
    } else
    if (a->diff == -2) {
        if (a->left->diff == 1)
            rotate_left(&a->left);
        rotate_right(rp);
        return 1;
    }
    return 0;
}

/* Initialize Node structure */
static int insert_leaf(size_t size, node **rp, void *block) {
    node *a = (*rp = (node *)block);
    *a = (node){ .next = NULL, .prev = NULL, .left = NULL, .right = NULL, .diff = 0 };
    return 1;
}

/* Expand Free List with the same size */
static int insert_list(node *a, void *block) {
    node *ptr = (node *)block;
    *ptr = (node){ .next = NULL, .prev = NULL, .left = NULL, .right = NULL, .diff = 0 };

    ptr->prev = a;
    a->next = ptr;
    return 0;
}

static int avl_insert(size_t size, node **rp, void *block) {
    node *a = *rp;
    if (a == NULL)
        return insert_leaf(size, rp, block);
    // if (size == a->size)
    if (size == getSize(a))
        return insert_list(a, block);
    // if (size > a->size)
    if (size > getSize(a))
        if (avl_insert(size, &a->right, block) && (++a->diff) == 1)
            return 1;
    if (size < getSize(a))
        if (avl_insert(size, &a->left, block) && (--a->diff) == -1)
            return 1;
    if (a->diff != 0)
        balance(rp);
    return 0;
}


static int unlink_left(node **rp, node **lp) {
    node *a = *rp;
    if (a->left == NULL) {
        *rp = a->right;
        *lp = a;
        return 1;
    }
    if (unlink_left(&a->left, lp) && (++a->diff) == 0)
        return 1;
    if (a->diff != 0)
        return balance(rp) && (*rp)->diff == 0;
    return 0;
}


static int remove_root(node **rp, void *block) {
    int delta;
    node *a = *rp, *b;
    if (a->prev != NULL || a->next != NULL) {
        node *next = ((node *)block)->next;
        node *prev = ((node *)block)->prev;
        if (prev != NULL) {
            if ((char *)a == (char *)block) {
                node *prev_ = prev->prev;
                *prev = *a;
                prev->prev = prev_;
                *rp = prev;
            }
            prev->next = next;
        }
        if (next != NULL) {
            if ((char *)a == (char *)block) {
                node *next_ = next->next;
                *next = *a;
                next->next = next_;
                *rp = next;
            }
            next->prev = prev;
        }
        return 0;
    }
    if (a->left == NULL || a->right == NULL) {
        *rp = a->right == NULL ? a->left : a->right;
        // free(a);
        return 1;
    }
    delta = unlink_left(&a->right, rp);
    b = *rp;
    b->left = a->left;
    b->right = a->right;
    b->diff = a->diff;
    // free(a);
    if (delta && (--b->diff) == 0)
        return 1;
    if (b->diff != 0)
        return balance(rp) && (*rp)->diff == 0;
    return 0;
}


static int avl_remove(size_t size, node **rp, void *block) {
    node *a = *rp;
    if (a == NULL)
        return 0;
    if (size == getSize(a))
        return remove_root(rp, block);
    if (size > getSize(a))
        if (avl_remove(size, &a->right, block) && (--a->diff) == 0)
            return 1;
    if (size < getSize(a))
        if (avl_remove(size, &a->left, block) && (++a->diff) == 0)
            return 1;
    if (a->diff != 0)
        return balance(rp) && (*rp)->diff == 0;
    return 0;
}

void avl_show(node *a) {
    if (a == NULL)
        return 0;

    avl_show(a->left);

    printf("|%7s - %15p|%7s - %15p|%7s - %15p|%7s - %7zu|\n", "addr", a, "left", a->left, "right",
                                     a->right, "size", getSize(a));
    avl_show(a->right);
}


void remove_from_free_list(void *ptr) {
    // Mark block as used.
    setFree(ptr, false);
    if (((Header *)ptr)->size >= NODE_SIZE) {
        avl_remove(((Header *)ptr)->size, &avl_root, add_offset(ptr));
    } else {
        free_list *free_block = (free_list *)add_offset(ptr);
        free_list *next = free_block->next;
        free_list *prev = free_block->prev;
        if (prev == NULL) {
            if (next == NULL) {
                // free_block is the only block in the free list.
                free_list_start = NULL;
            } else {
                // Remove first element in the free list.
                free_list_start = next;
                next->prev = NULL;
            }
        } else {
            if (next == NULL) {
                // Remove last element of the free list.
                prev->next = NULL;
            } else {
                // Remove element in the middle.
                prev->next = next;
                next->prev = prev;
            }
        }
    }
}

void append_to_free_list(void *ptr) {
    // Mark block as free
    setFree(ptr, true);

    if (((Header *)ptr)->size >= NODE_SIZE) {
        avl_insert(((Header *)ptr)->size, &avl_root, add_offset(ptr));
    } else {
        free_list *new_ptr = (free_list *)add_offset(ptr);
        *new_ptr = (free_list){ .next = NULL, .prev = NULL };

        if (free_list_start) {
            // Insert in the beginning.
            new_ptr->next = free_list_start;
            free_list_start->prev = new_ptr;
            free_list_start = new_ptr;
        } else {
            // No elements in the free list
            free_list_start = new_ptr;
        }
    }
}

// Find a free block that is large enough to store 'size' bytes.
// Returns NULL if not found.
void *find_small_free_block(size_t size) {
    free_list *current = free_list_start;
    while (current) {
        if (getSize(current) >= size) {
            // Return a pointer to the free block.
            return current;
        }
        current = current->next;
    }
    return NULL;
}

void *find_free_block(size_t size) {
    if (size < NODE_SIZE)
        return find_small_free_block(size);
    node *curr = avl_root;
    while (curr) {
        size_t curr_size = getSize(curr);
        if (size == curr_size)
            return curr;
        if (size > curr_size)
            curr = curr->right;
        if (size < curr_size) {
            if ((curr->left == NULL) || (size >= getSize(curr->left)))
                return curr;
            curr = curr->left;
        }
    }
    return NULL;
}

// Split memory into multiple blocks after some part of it was requested
// (requested + the rest).
void split(void *start_ptr,  size_t requested) {
    size_t curr_size = getSize(add_offset(start_ptr));

    // Size that was left after allocating memory.
    // Needs to be large enough to store another block (min size is needed in order
    // to store free list element there after it is freed).
    if ((curr_size <= requested) || ((curr_size - requested) <= NODE_SIZE)) {
        return;
    }

    size_t block_size = curr_size - requested;
    void *new_block_ptr = (void *)((char *)start_ptr + requested);

    // Change size of the prev (recently allocated) block.
    setSizeHeader(start_ptr, requested - META_SIZE);
    ((Header *)start_ptr)->has_next = true;
    Footer start_footer = { .size = requested - META_SIZE, .free = ((Header *)start_ptr)->free};
    *((Footer *)getFooter(start_ptr)) = start_footer;

    // Add a header for newly created block (right block).
    Header *new_block_header = (Header *)new_block_ptr;
    *new_block_header = (Header){ .size = block_size, .free = true, .has_prev = true, .has_next = ((Header *)start_ptr)->has_next};

    Footer footer = { .size = block_size, .free = true};
    *((Footer *)getFooter(new_block_header)) = footer;
    append_to_free_list(new_block_header);
}


void *mem_alloc(size_t size) {
    if (size <= 0) {
        return NULL;
    }
    // Round allocation size up to an appropriate alignment
    size_t required_size = ALIGN(size + META_SIZE, alignof(max_align_t));
    if (required_size - META_SIZE <= 0) {
        return NULL;
    }

    // Try to find a block big enough in already allocated memory.
    void *free_block = find_free_block(required_size);
    // void *free_block = find_free_block(required_size, avl_root);
    if (free_block == NULL) {
       // Round to a multiple of the page size
        size_t bytes = ALIGN(required_size + NODE_SIZE, PAGE_SIZE);

    // Request some more memory from the kernel
#ifdef __unix__
        void *new_region = mmap(last_address, bytes, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
#else
        void *new_region = VirtualAlloc(NULL, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
#endif // __unix__

        // On Failed for both System
        if (new_region == MAP_FAILED) {
            return NULL;
        }
        // Create a header/footer for new block.
        Header *header_ptr = (Header *)new_region;
        *header_ptr = (Header){ .size = bytes - META_SIZE, .free = false, .has_next = false, .has_prev = false};

        Footer footer = { .size = bytes - META_SIZE, .free =  false };
        *((Footer *)getFooter(header_ptr)) = footer;

        // Split new region.
        // split(header_ptr, MAX(required_size, NODE_SIZE));
        split(header_ptr, required_size);
        // Update last_address for the next allocation.
        last_address = (void *)((char *)header_ptr + bytes);
        // Return address behind the header (i.e. header is hidden).
        return add_offset(header_ptr);
    }

    // Header ptr
    void *address = remove_offset(free_block);
    // Split the block into two, where the second is free.
    remove_from_free_list(address);
    // split(address, MAX(required_size, NODE_SIZE));
    split(address, required_size);
    return add_offset(address);
}

void coalesce(void *ptr) {
    Header *current_header = (Header *)ptr;
    Footer *current_footer = (Footer *)getFooter(ptr);
    if (current_header->has_prev && ((Footer *)((char *)ptr - FOOTER_SIZE))->free) {
        Footer *prev_footer = (Footer *)((char *)ptr - FOOTER_SIZE);
        Header *prev_header = (Header *)((char *)prev_footer - prev_footer->size - HEADER_SIZE);
        // Merge with previous block.
        remove_from_free_list(current_header);
        remove_from_free_list(prev_header);
        // Add size of prev block to the size of current block
        prev_header->size += current_header->size + META_SIZE;
        prev_header->has_next = current_header->has_next;
        ((Footer *)getFooter(prev_header))->size = prev_header->size;
        append_to_free_list(prev_header);
        current_header = prev_header;
    }
    void *next = (void *)((char *)current_header + current_header->size + META_SIZE);
    if (current_header->has_next && ((Header *)next)->free) {
        // merge with next block.
        remove_from_free_list(next);
        remove_from_free_list(current_header);
        // Add size of next block to the size of current block.
        current_header->size += ((Header *)next)->size + META_SIZE;
        current_header->has_next = ((Header *)next)->has_next;
        ((Footer *)getFooter(current_header))->size = current_header->size;
        append_to_free_list(current_header);
    }
}

int _free(void *ptr, size_t size) {
#ifdef __unix__
    return munmap(ptr, size);
#else
    return VirtualFree(ptr, 0, MEM_RELEASE)
#endif // __unix__
}

void mem_free(void *ptr) {
    if (ptr == NULL) {
        return;
    }

    Header *header = (Header *)remove_offset(ptr);

    // Check if it has already been freed.
    // Does not handle case when start_address passed was never allocated.
    if (header->free) {
        return;
    }

    // Add block into the free list
    append_to_free_list((void *)header);

    // Coalesce with any neighboring free blocks
    coalesce((void *)header);
}

void *mem_realloc(void *ptr, size_t size) {
    // If ptr is NULL, realloc() is identical to a call to malloc() for size bytes.
    if (ptr == NULL) {
        return mem_alloc(size);
    }
    // If size is zero and ptr is not NULL, a new, minimum sized object (MIN_SIZE) is
    // allocated and the original object is freed.
    if (size == 0) {
        mem_free(ptr);
        return NULL;
    }

    size_t required_size = ALIGN(size + META_SIZE, alignof(max_align_t));

    // Find header for the user data
    Header *current_header = (Header *)remove_offset(ptr);
    Footer *current_footer = (Footer *)getFooter(current_header);

    // If there is enough space, expand the block.
    size_t current_size = getSize(ptr);

    // if user requests to shorten the block.
    if (required_size <= current_size) {
        split(current_header, required_size);
        return ptr;
    }

    // Next block exists and is free.
    void *next = (void *)((char *)current_header + current_header->size + META_SIZE);
    if (current_header->has_next && ((Header *)next)->free) {
        size_t available_size = current_size + ((Header *)next)->size + META_SIZE;
        // Size is enough.
        if (available_size >= required_size) {
            remove_from_free_list(next);
            // Add size of next block to the size of current block.
            current_header->size = available_size;
            current_header->has_next = ((Header *)next)->has_next;
            current_footer->size = available_size;

            // split if possible.
            split(current_header, required_size);
            return ptr;
        }
    }

    // Not enough room to enlarge -> allocate new region.
    void *new_ptr = mem_alloc(size);
    if (new_ptr != NULL) {
        // Copy old data.
        memcpy(new_ptr, ptr, current_size);
        // Free old location.
        mem_free(ptr);
    }
    return new_ptr;
}

void mem_show(void *ptr) {
    if (ptr == NULL) {
        return;
    }

    Header *addr = (Header *)remove_offset(ptr);
    printf("|%7s - %15p|%7s - %7d|%7s - %7zu|%7s - %7d|%7s - %7d|\n", "addr", addr, "free", addr->free, "size",
                                     addr->size, "prev", addr->has_prev, "next", addr->has_next);
}
