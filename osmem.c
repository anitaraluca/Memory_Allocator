// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include <sys/types.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <string.h>
#include "block_meta.h"

#define MMAP_THRESHOLD 131072
#define META_SIZE (sizeof(struct block_meta))
#define MIN_BLOCK_SIZE ALIGN(META_SIZE)

struct block_meta *global_base;
int preallocated;

struct block_meta *best_block(size_t size)
{
	struct block_meta *ptr = global_base;
	struct block_meta *block = NULL;
	size_t min_diff = MMAP_THRESHOLD;

	for (; ptr; ptr = ptr->next) {
		if (ptr->status == STATUS_FREE && ptr->size >= size) {
			size_t diff = ptr->size - size;

			if (diff < min_diff) {
				min_diff = diff;
				block = ptr;
			}
		}
	}
	return block;
}

struct block_meta *request_space(size_t size, int call)
{
	struct block_meta *block;
	size_t k = 0;

	if (call == 0)
		k = MMAP_THRESHOLD;
	else if (call == 1)
		k = sysconf(_SC_PAGESIZE);
	if (size < k) {
		void *request = sbrk(size);

		if (request == (void *)-1) {
			DIE(request, "sbrk");
		} else {
			block = (struct block_meta *)request;
			block->size = size;
			block->next = NULL;
			block->status = STATUS_ALLOC;
		}
	} else {
		void *req = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		if (req == MAP_FAILED)
			DIE(req, "mmap");

		block = (struct block_meta *)req;
		block->size = size;
		block->next = NULL;
		block->status = STATUS_MAPPED;
	}
	return block;
}

void split_block(struct block_meta *block, size_t req_size)
{
	if (block->size - req_size < MIN_BLOCK_SIZE)
		return;
	struct block_meta *new_block = (struct block_meta *)((char *)block + req_size);

	new_block->status = STATUS_FREE;
	new_block->size = block->size - req_size;
	new_block->next = block->next;
	new_block->prev = block;

	block->size = req_size;
	block->next = new_block;

	return (struct block_meta *)((char *)global_base - MIN_BLOCK_SIZE);
}

struct block_meta *coalesce_blocks(void)
{
	struct block_meta *current = global_base;
	struct block_meta *prev = NULL;

	for (; current; prev = current, current = current->next) {
		if (current->status == STATUS_FREE)	{
			if (current->next && current->next->status == STATUS_FREE) {
				current->size = current->size + current->next->size;
				current->next = current->next->next;
				if (current->next)
					current->next->prev = current;
			}
			if (prev && prev->status == STATUS_FREE) {
				prev->size = prev->size + current->size;
				prev->next = current->next;
				if (current->next)
					current->next->prev = prev;
				current = prev;
			}
		}
	}
	return prev;
}

void prealloc_memory(size_t size, int call)
{
	int k = 0;

	if (call == 0)
		k =   MMAP_THRESHOLD;
	else
		k = sysconf(_SC_PAGESIZE);
	if (preallocated == 0 && MIN_BLOCK_SIZE + ALIGN(size) < k && !global_base) {
		global_base = sbrk(MMAP_THRESHOLD);

		DIE(global_base == (void *)-1, "sbrk");

		global_base->status = STATUS_FREE;
		global_base->size = MMAP_THRESHOLD;
	}

	preallocated = 1;
	return (struct block_meta *)((char *)global_base - MIN_BLOCK_SIZE);
}

void *implement(size_t size, int call)
{
	struct block_meta *last = coalesce_blocks();
	int aligned_size = MIN_BLOCK_SIZE + ALIGN(size);
	struct block_meta *block = best_block(aligned_size);

	if (block) {
		if (block->size >= aligned_size + ALIGN(META_SIZE + ALIGN(1)))
			split_block(block, aligned_size);
		block->status = STATUS_ALLOC;
	} else {
		if (last && last->status == STATUS_FREE) {
			block = request_space(aligned_size - last->size, call);
			last->size = last->size + block->size;
			block = last;

		if (block->size >= aligned_size + ALIGN(META_SIZE + ALIGN(1))) {
			split_block(block, aligned_size);
			block->status = STATUS_ALLOC;
		}

		} else {
			block = request_space(aligned_size, call);
			if (block->status == STATUS_ALLOC && last)
				last->next = block;
		}
	}
	if (call == 1)
		memset((void *)block + MIN_BLOCK_SIZE, 0, size);

	return (void *)block + MIN_BLOCK_SIZE;
}

void *os_malloc(size_t size)
{
	/* TODO: Implement os_malloc */
	if (size != 0) {
		prealloc_memory(size, 0);
		implement(size, 0);
	}
	if (size == 0)
		return NULL;
}

void os_free(void *ptr)
{
	/* TODO: Implement os_free */
	if (ptr == NULL)
		return;

	struct block_meta *block = (struct block_meta *)((char *)ptr - MIN_BLOCK_SIZE);

	if (block->status == STATUS_ALLOC)
		block->status = STATUS_FREE;
	if (block->status == STATUS_MAPPED) {
		int ret = munmap(block, block->size);

		if (ret == -1)
			DIE(ret, "munmap");
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
	if (nmemb != 0 && size != 0) {
		int total_size = size * nmemb;

		prealloc_memory(total_size, 1);
		implement(total_size, 1);
	}
	if (nmemb == 0 || size == 0)
		return NULL;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	if (!ptr)
		return os_malloc(size);
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
}
