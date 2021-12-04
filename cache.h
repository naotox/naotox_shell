#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_CACHE_SIZE (1024 * 1024)
#define MAX_OBJECT_SIZE (100 * 1024)
#define MAXLINE 8192

/** basic node structure: nodes connected by single linked list
 * 1.next pointer pointing to the next node
 * 2.URL that serves as a search key
 * 3.Contents are stored in store
 * 4.size: the size of content
 * 5.LRU : a parameter for determining who to evict
 */
typedef struct node {
    struct node *next;
    char URL[MAXLINE];
    char *store;
    size_t size;
    int LRU;
} node_t;

/**
 * basic cache structure:
 * 1. header node: only a header, contains nothing
 * 2. total size of stored contents
 * 3. ref: a reference LRU counter
 */
typedef struct cache {
    node_t *header;
    int total_size;
    int ref;
} cache_t;

cache_t *cache_init(void);
bool cache_exist(cache_t *cache, char *URL, node_t **retval);
char *cache_read_result(cache_t *cache, node_t *node);
void cache_store(cache_t *cache, char *store, char *URL, int size);
size_t cache_size(node_t *node);
void cache_free(cache_t *cache);