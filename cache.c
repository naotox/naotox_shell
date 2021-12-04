#include "cache.h"
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MAX_CACHE_SIZE (1024 * 1024)
#define MAX_OBJECT_SIZE (100 * 1024)
#define MAXLINE 8192
/** This is an implementation of a simple software cache
 *  It applies LRU policy for eviction.
 *  The cache will always have a header node that has nothing stored.
 *  Other nodes are connected by single linked list.
 */

// initiate cache and its header node
cache_t *cache_init(void) {
    cache_t *new = malloc(sizeof(cache_t));
    node_t *temp = malloc(sizeof(node_t));
    temp->next = NULL;
    strcpy(temp->URL, "");
    temp->store = NULL;
    temp->size = 0;
    temp->LRU = INT_MAX;
    new->header = temp;
    new->total_size = 0;
    new->ref = 0;
    return new;
}

// return the size of a given node
size_t cache_size(node_t *node) {
    return node->size;
}

// Given a URL as a key, the function
// check through the list whether a given URL exists in the cache.
// return true if found and false otherwise
// if true is returned, the function will fill retval with a pointer
// to the corresponding node
bool cache_exist(cache_t *cache, char *URL, node_t **retval) {
    node_t *temp;
    for (temp = cache->header; temp != NULL; temp = temp->next) {
        if (memcmp(URL, temp->URL, MAXLINE) == 0) {
            *retval = temp;
            return true;
        }
    }
    return false;
}

// read the stored content of a node
// will refresh the node's LRU
// return the store content
char *cache_read_result(cache_t *cache, node_t *node) {
    cache->ref++;
    node->LRU = cache->ref;
    return (node->store);
}

// will delete the cache node with the lowest LRU
// free the memory occupied by the freed block
void delete_cache_node(cache_t *cache) {
    node_t *temp = cache->header->next;
    node_t *least = temp;
    while (temp != NULL) {
        if (temp->LRU < least->LRU) {
            least = temp;
        }
        temp = temp->next;
    }
    cache->total_size -= least->size;
    node_t *first = cache->header;
    node_t *second = least->next;
    free(least->store);
    free(least);
    while (first->next != least) {
        first = first->next;
    }
    first->next = second;
}

// store the URL key and its correspoding content into the cache
// if cache maximum size is exceeded, evict one or more nodes to
// maintain the maximum size.
void cache_store(cache_t *cache, char *store, char *URL, int size) {
    node_t *meaningless;
    // check if we store redundant copies
    if (cache_exist(cache, URL, &meaningless)) {
        return;
    }
    cache->total_size += size;
    // evict nodes following policy of LRU
    while (cache->total_size > MAX_CACHE_SIZE) {
        delete_cache_node(cache);
    }
    node_t *new = malloc(sizeof(node_t));
    node_t *temp = cache->header->next;
    cache->ref++;
    new->LRU = cache->ref;
    new->next = temp;
    strcpy(new->URL, URL);
    new->size = size;
    new->store = store;
    cache->header->next = new;
}

// free the entire cache
void cache_free(cache_t *cache) {
    node_t *temp = cache->header->next;
    while (temp != NULL) {
        node_t *nextfree = temp->next;
        free(temp->store);
        free(temp);
        temp = nextfree;
    }
    free(cache->header);
    free(cache);
}
