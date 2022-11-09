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

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

#define CHUNK_SIZE (1 << 10)
#define WSIZE 4
#define DSIZE (WSIZE << 1)
#define DSIZE_MASK ~0x7
#define ALLOCATE 0x1
#define FREED 0x0

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

static void *first_hdr_block;
static void *heap_extend(size_t size);

static int mm_check(void){
	void *hdr = first_hdr_block;
	void *block = hdr + WSIZE;
	void *ftr = ftr(block);

	void *heap_start = mem_heap_lo();
	void *heap_end = mem_heap_hi();

	printf("heap_start: %p\n", heap_start);
	printf("prologue hdr: %p\n", heap_start + WSIZE);
	printf("prologue ftr: %p\n", heap_start + DSIZE);
	printf("epilogue: %p\n", heap_end - WSIZE);

	while(get_size(hdr) != 0){
		printf("-------------------------------\n");
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

		block = next_block(block);
		hdr = hdr(block);
		ftr = ftr(block);
	}

	printf("epilogue: %p\n", heap_end - WSIZE);
	return 1;
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

    first_hdr_block = epilogue;

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
    return 0;
}

/*
 * first_fit - Find the first suitable chunk for the size bytes 
 */
static void *first_fit(size_t size){
	void *block = first_hdr_block + WSIZE;
	size_t block_size = get_size(hdr(block));
	int allocate_bit = get_alloc_bit(hdr(block));

	while(block_size != 0){              // epilogue size will be 0
		if(FREED == allocate_bit && block_size >= size)
			return block;

		block = next_block(block);
		allocate_bit = get_alloc_bit(hdr(block));
		block_size = get_size(hdr(block));
	}

	return NULL;
}

/*
 * merge_free_blocks - merge continuous free blocks
 * 	
 */
static void *merge_free_blocks(void *block){
	// four cases
	
	void *merge_block = block;

	//mm_check();
	int prev_alloc = get_alloc_bit(ftr(prev_block(block)));
	int next_alloc = get_alloc_bit(hdr(next_block(block)));
	//printf("prev(addr: %p): %d, next(addr: %p): %d\n", prev_block(block), prev_alloc, next_block(block), next_alloc);

	if(prev_alloc && next_alloc){         // first case: previous block and next block are not freed
		goto ret;
	} else if(prev_alloc && !next_alloc){ // second case: previous block is not freed but next block is freed
		/*
		set_size(hdr(block), get_size(hdr(block)) + get_size(hdr(next_block(block))));
		set_allocate_bit(hdr(block), FREED);
		set_word(ftr(next_block(block)), get_word(hdr(block)));
		merge_block = block;
		*/
	} else if(!prev_alloc && next_alloc){ // third case: previous block is freed but next block is not freed
		set_size(hdr(prev_block(block)), get_size(hdr(prev_block(block))) + get_size(hdr(block)));
		set_allocate_bit(hdr(prev_block(block)), FREED);
		set_word(ftr(block), get_word(hdr(prev_block(block))));
		merge_block = prev_block(block);
	} else {                             // forth case: previous block and next block are freed
		/*
		set_size(hdr(prev_block(block)), get_size(hdr(prev_block(block))) + 
							get_size(hdr(block)) + 
							get_size(hdr(next_block(block))));
		set_allocate_bit(hdr(prev_block(block)), FREED);
		set_word(ftr(next_block(block)), get_word(hdr(prev_block(block))));
		merge_block = prev_block(block);
		*/
	}

	/*
	printf("--------------------------------Merged------------------------\n");
	mm_check();
	printf("--------------------------------Done------------------------\n");
	*/

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
	set_hdr_ftr_size_and_alloc(block, size, FREED);

	//printf("new data block: %p, size: %zu\n", block, size);

	// new epilogue
	void *epilogue = hdr(next_block(block));
        set_size(epilogue, 0);
        set_allocate_bit(epilogue, ALLOCATE);

	return block;
	
	// previous block of free_block could be merged
	//return merge_free_blocks(block);
}

void mark_used(void *free_block, size_t size){
	size_t left = get_size(hdr(free_block)) - size;
	
	// check if left space is enough for minimal block which is 16 bytes(4 bytes for hdr, 8 bytes for data(8-aligned), 4 bytes for ftr)
	if(left < 16){ // simply mark used because next mm_malloc will call heap_extend
		set_hdr_ftr_size_and_alloc(free_block, get_size(hdr(free_block)), ALLOCATE);
	} else { // to prevent next mm_malloc calls heap_extend and wastes left space, we need to mark next hdr and ftr
		set_hdr_ftr_size_and_alloc(free_block, size, ALLOCATE);
		set_hdr_ftr_size_and_alloc(next_block(free_block), left, FREED);
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

	size_t org_size = size;
	/*
	printf("----------------------Before---------------------\n");
	printf("orig size: %zu\n", size);
	mm_check();
	*/
	/*
	if(size <= DSIZE)
		size =  2 * DSIZE;
	else
		size = DSIZE * ((size + (DSIZE) + (DSIZE - 1)) / DSIZE);
		*/

	if(size <= DSIZE)
		size = (DSIZE << 1); // size = 2 * DSIZE, 1 DSIZE for header and footer, 1 DSIZE for data
	else
		size = ALIGN(size) + DSIZE; // size = ALIGN(size) + DSIZE, 1 DSIZE for header and footer, ALIGN(size) for data

	// check the remaining space if is enough for size bytes
	void *free_block = first_fit(size);
	if(free_block)
		goto return_free_block_and_mark_used;

	// remaining space in heap is not enough, so try to extend the heap
	free_block = heap_extend(max(size, CHUNK_SIZE));
	if(!free_block)
		return NULL;
	
return_free_block_and_mark_used:
	mark_used(free_block, size);
	/*
	printf("------------------------After-----------------------\n");
	mm_check();
	printf("return free_block: %p, size: %zu\n", free_block, size);
	printf("------------------------Done------------------------\n");
	printf("orig size: %zu\n", org_size);
	*/
	return free_block;

	/*
    int newsize = ALIGN(size + SIZE_T_SIZE);
    void *p = mem_sbrk(newsize);
    if (p == (void *)-1)
	return NULL;
    else {
        *(size_t *)p = size;
        return (void *)((char *)p + SIZE_T_SIZE);
    }
    */
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr)
{
	if(!ptr)
		return;

	set_hdr_ftr_size_and_alloc(ptr, get_size(hdr(ptr)), FREED);
	//size_t size = get_size(hdr(ptr));
	//printf("free size: %u\n", size);
	//merge_free_blocks(ptr);
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
    copySize = *(size_t *)((char *)oldptr - SIZE_T_SIZE);
    if (size < copySize)
      copySize = size;
    memcpy(newptr, oldptr, copySize);
    mm_free(oldptr);
    return newptr;
}














