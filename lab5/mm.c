/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 * 
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
    /* Team name */
    "CCU",
    /* First member's full name */
    "Chin Yik Ming",
    /* First member's email address */
    "tym108u@cs.ccu.edu.tw",
    /* Second member's full name (leave blank if none) */
    "",
    /* Second member's email address (leave blank if none) */
    ""
};

typedef void *(*find_fit_algo)(size_t size);

find_fit_algo find_fit;

#ifdef DEBUG
#define heap_check(verbose) printf("-----------------%s------------------\n", __func__); \
                        	if(mm_check(verbose)){ \
					printf("Overlapped!\n"); \
					exit(1); \
				}
#endif

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

#define CHUNK_SIZE (1 << 12)
#define WSIZE 4
#define DSIZE (WSIZE << 1)
#define DSIZE_MASK ~0x7
#define ALLOCATE 0x1
#define FREE 0x0

/* used to determine new brk offset which should be max(size, max chunk) */
#define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

/* macro to manipulate the implicit list */
#define get_word(addr) \
	(*(unsigned int *) (addr))

#define set_word(addr, val) \
	(*(unsigned int *) (addr) = (val))

#define get_size(addr) \
	((*(unsigned int *) (addr)) & DSIZE_MASK)

#define set_size(addr, size) \
	set_word(addr, size)

#define get_alloc_bit(addr) \
	((*(unsigned int *) (addr)) & ALLOCATE)

#define set_allocate_bit(addr, a) \
	set_word(addr, (*(unsigned int *) (addr)) | (a))

#define hdr(block) \
	((char *)(block) - WSIZE)

#define ftr(block) \
	((char *)(block) + get_size(hdr(block)) - DSIZE)

#define prev_ftr(block) \
	((char *)(block) - DSIZE)

#define prev_block(block) \
	((char *)(block) - get_size(prev_ftr(block)))

#define next_block(block) \
	((char *)(block) + get_size(hdr(block)))

static void *first_hdr;
static void *heap_extend(size_t size);
static void *first_fit(size_t size);
static void *best_fit(size_t size);
static void *worst_fit(size_t size);
static void *next_fit(size_t size);
static void *last_search;                       // used by next_fit function

static int mm_check(int verbose){
	void *hdr = first_hdr;
	void *block = hdr + WSIZE;
	void *ftr = ftr(block);

	void *heap_start = mem_heap_lo();
	void *heap_end = mem_heap_hi();

	if(verbose){
		printf("heap_start: %p\n", heap_start);
		printf("prologue hdr: %p\n", heap_start + WSIZE);
		printf("prologue ftr: %p\n", heap_start + DSIZE);
		printf("epilogue: %p\n", heap_end - WSIZE);
	}

	int counter = 1;
	while(get_size(hdr) != 0){
		if(verbose){
			printf("-------------------------------\n");
			printf("-----------counter %d-------------\n", counter);
			if(get_alloc_bit(hdr))
				printf("Alloc\n");
			else
				printf("Freed\n");
			// hdr
			printf("hdr: %u, %p\n", get_word(hdr), hdr);
			// block
			printf("block addr: %p, block size: %zu\n", block, get_size(hdr));
			// ftr	
			printf("ftr: %u, %p\n", get_word(ftr), ftr);
			printf("-------------------------------\n");
		}

		block = next_block(block);
		hdr = hdr(block);
		ftr = ftr(block);
		counter++;
	}


	/*
	// check overlapping
	void *blocki, *blockj;
	int allocate_bit;
	void *hi, *hi2, *lo, *lo2;
	int counter1 = 1, counter2 = 1;
	for(blocki = first_hdr + WSIZE; get_size(hdr(blocki)) != 0; blocki = next_block(blocki)){
		lo = blocki;
		hi = ftr(blocki);

		counter2 = 1;
		for(blockj = next_block(blocki); get_size(hdr(blockj)) != 0; blockj = next_block(blockj)){
			lo2 = blockj;
			hi2 = ftr(blockj);
				
			if((lo >= lo2 && lo <= hi2) || 
			   (hi >= lo2 && hi <= hi2)){
				printf("block %d overlaped block %d\n", counter2, counter1);
				return 1;
			}
			
			counter2++;
		}

		counter1++;
	}
	*/

	if(verbose){
		printf("epilogue: %p\n", heap_end - WSIZE);
	}
	return 0;
}

static void set_hdr_ftr_size_and_alloc(void *block, size_t size, int alloc){
    set_size(hdr(block), size);
    set_allocate_bit(hdr(block), alloc);
    set_word(ftr(block), get_word(hdr(block)));
}
	
/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
    void *old_brk = mem_sbrk(4 * WSIZE);
    if((void *)-1 == old_brk){
	fprintf(stderr, "mm_init with mem_sbrk failed!\n");
    	return -1;
    }

    // heap_start should be aligned to 8, so no padding here
    void *heap_start = mem_heap_lo();

    // set prologue header, prologue footer, epilogue
    void *padding = heap_start;
    void *prologue_hdr = heap_start + WSIZE;
    void *prologue_ftr = heap_start + DSIZE;
    void *epilogue = heap_start + (DSIZE + WSIZE);

    first_hdr = epilogue;

    // unused padding
    set_size(padding, 0);

    // prologue
    set_size(prologue_hdr, 8); // 8 is prologue hdr + prologue ftr
    set_allocate_bit(prologue_hdr, ALLOCATE);
    set_word(prologue_ftr, get_word(prologue_hdr)); // footer is a copy of header

    // epilogue
    set_size(epilogue, 0);
    set_allocate_bit(epilogue, ALLOCATE);

    if(!heap_extend(CHUNK_SIZE)){
	    printf(stderr, "mm_init with heap_extend failed!\n");
	    return -1;
    }

#ifdef FF
	find_fit = first_fit;
#endif
#ifdef NF
	find_fit = next_fit;
	last_search = ((char *) first_hdr) + WSIZE;
#endif
#ifdef BF
	find_fit = best_fit;
#endif
#ifdef WF
	find_fit = worst_fit;
#endif

    return 0;
}

/*
 * first_fit - Find the first suitable chunk for the size bytes 
 */
static void *first_fit(size_t size){
	void *block = first_hdr + WSIZE;
	size_t block_size = get_size(hdr(block));
	int allocate_bit = get_alloc_bit(hdr(block));

	while(block_size != 0){              // epilogue size will be 0
		if(FREE == allocate_bit && block_size >= size)
			return block;

		block = next_block(block);
		allocate_bit = get_alloc_bit(hdr(block));
		block_size = get_size(hdr(block));
	}

	return NULL;
}

/*
 * next_fit - Find the first suitable chunk for the size bytes from last search
 */
static void *next_fit(size_t size){
	void *block = last_search;
	size_t block_size = get_size(hdr(block));
	int allocate_bit = get_alloc_bit(hdr(block));

	// last_search ---> epilogue
	while(block_size != 0){              // epilogue size will be 0
		if(FREE == allocate_bit && block_size >= size){
			last_search = block;
			return block;
		}

		block = next_block(block);
		allocate_bit = get_alloc_bit(hdr(block));
		block_size = get_size(hdr(block));
	}

	// start block ---> previous block of last_search
	block = first_hdr + WSIZE;
	block_size = get_size(hdr(block));
	allocate_bit = get_alloc_bit(hdr(block));
	while(block != last_search){
		if(FREE == allocate_bit && block_size >= size){
			last_search = block;
			return block;
		}
	
		block = next_block(block);
		allocate_bit = get_alloc_bit(hdr(block));
		block_size = get_size(hdr(block));
	}

	return NULL;
}

/*
 * best_fit - Find the smallest suitable chunk for the size bytes 
 */
static void *best_fit(size_t size){
	void *blocki, *blockj, *best = NULL;
	int allocate_bit;
	for(blocki = first_hdr + WSIZE; get_size(hdr(blocki)) != 0; blocki = next_block(blocki)){
		allocate_bit = get_alloc_bit(hdr(blocki));
		if(FREE == allocate_bit && get_size(hdr(blocki)) >= size){
			best = blocki;

			for(blockj = next_block(blocki); get_size(hdr(blockj)) != 0; blockj = next_block(blockj)){
				allocate_bit = get_alloc_bit(hdr(blockj));
				if(FREE == allocate_bit && 
				   get_size(hdr(blockj)) >= size &&
				   get_size(hdr(blockj)) < get_size(hdr(best))){
					best = blockj;
				}

			}
		}
	}
	return best;
}

/*
 * worst_fit - Find the largest suitable chunk for the size bytes 
 */
static void *worst_fit(size_t size){
	void *blocki, *blockj, *worst = NULL;
	int allocate_bit;
	for(blocki = first_hdr + WSIZE; get_size(hdr(blocki)) != 0; blocki = next_block(blocki)){
		allocate_bit = get_alloc_bit(hdr(blocki));
		if(FREE == allocate_bit && get_size(hdr(blocki)) >= size){
			worst = blocki;

			for(blockj = next_block(blocki); get_size(hdr(blockj)) != 0; blockj = next_block(blockj)){
				allocate_bit = get_alloc_bit(hdr(blockj));
				if(FREE == allocate_bit && 
				   get_size(hdr(blockj)) >= size &&
				   get_size(hdr(blockj)) > get_size(hdr(worst))){
					worst = blockj;
				}

			}
		}
	}
	return worst;
}

/*
 * merge_free_blocks - merge continuous free blocks
 * 	
 */
static void *merge_free_blocks(void *block){
	void *merge_block = block;

	int prev_alloc = get_alloc_bit(ftr(prev_block(block)));
	int next_alloc = get_alloc_bit(hdr(next_block(block)));
	size_t size = 0;

	if(prev_alloc && next_alloc){         // case one: previous block and next block are not freed
		goto ret;
	} else if(prev_alloc && !next_alloc){ // case two: previous block is not freed but next block is freed
		size += get_size(hdr(block)) + get_size(hdr(next_block(block)));
		merge_block = block;
	} else if(!prev_alloc && next_alloc){ // case three: previous block is freed but next block is not freed
		size += get_size(hdr(prev_block(block))) + get_size(hdr(block));
		merge_block = prev_block(block);
	} else {                             // case four: previous block and next block are freed
		size += get_size(hdr(prev_block(block))) + get_size(hdr(block)) + get_size(hdr(next_block(block)));
		merge_block = prev_block(block);
	}

	set_size(hdr(merge_block), size);
	set_allocate_bit(hdr(merge_block), FREE);
	set_word(ftr(merge_block), get_word(hdr(merge_block)));
	last_search = merge_block; // update last search since merge_free_blocks could corrupt the last_search

ret:
	return merge_block;
}

/*
 * heap_extend - extend the brk pointer if available
 * 	Return first freed block if successful else NULL
 */
static void *heap_extend(size_t size){
	void *old_brk = mem_sbrk(size);
	if((void *)-1 == old_brk)
		return NULL;

	// old_brk becomes first freed data block
	void *block = old_brk;
	set_hdr_ftr_size_and_alloc(block, size, FREE);

	// new epilogue
	void *epilogue = hdr(next_block(block));
        set_size(epilogue, 0);
        set_allocate_bit(epilogue, ALLOCATE);
	
	// previous block of free_block could be merged
	return merge_free_blocks(block);
}

void mark_used(void *free_block, size_t size){
	size_t left = get_size(hdr(free_block)) - size;
	
	// check if left space is enough for minimal block which is 16 bytes(4 bytes for hdr, 8 bytes for data(8-aligned), 4 bytes for ftr)
	if(left < 16){ // simply mark used because next mm_malloc will call heap_extend
		set_hdr_ftr_size_and_alloc(free_block, get_size(hdr(free_block)), ALLOCATE);
	} else { // to prevent next mm_malloc calls heap_extend and wastes left space, we need to mark next hdr and ftr
		set_hdr_ftr_size_and_alloc(free_block, size, ALLOCATE);
		set_hdr_ftr_size_and_alloc(next_block(free_block), left, FREE);
	}
}

/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size)
{
	if(0 == size)
		return NULL;

#ifdef DEBUG
	size_t org_size = size;
	printf("----------------------Before---------------------\n");
	printf("orig size: %zu\n", size);
	heap_check(1);
#endif

	if(size <= DSIZE)
		size = (DSIZE << 1); // size = 2 * DSIZE, 1 DSIZE for header and footer, 1 DSIZE for data
	else
		size = ALIGN(size) + DSIZE; // size = ALIGN(size) + DSIZE, 1 DSIZE for header and footer, ALIGN(size) for data

	// check the remaining space if is enough for size bytes
	void *free_block = find_fit(size);
	if(free_block)
		goto return_free_block_and_mark_used;

	// remaining space in heap is not enough, so try to extend the heap
	free_block = heap_extend(max(size, CHUNK_SIZE));
	if(!free_block)
		return NULL;
	
return_free_block_and_mark_used:
	mark_used(free_block, size);

#ifdef DEBUG
	printf("------------------------After-----------------------\n");
	heap_check(1);
	printf("return free_block: %p, size: %zu\n", free_block, size);
	printf("------------------------Done------------------------\n");
#endif
	return free_block;
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr)
{
	if(!ptr)
		return;
#ifdef DEBUG
	heap_check(1);
	printf("free ptr: %p\n", ptr);
#endif

	set_hdr_ftr_size_and_alloc(ptr, get_size(hdr(ptr)), FREE);
	merge_free_blocks(ptr);
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size)
{
    void *oldptr = ptr;
    void *newptr;
    size_t copySize;
    
    newptr = mm_malloc(size);
    if (newptr == NULL)
      return NULL;
    copySize = get_size(oldptr) - DSIZE; // minus hdr and ftr size
    if (size < copySize)
      copySize = size;
    memcpy(newptr, oldptr, copySize);
    mm_free(oldptr);
    return newptr;
}

