#include "cachelab.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <assert.h>
#include <limits.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#define VALID 0x1
#define DIRTY 0x1
#define PATH_MAX 4096

int hit_cnt;
int miss_cnt;
int eviction_cnt;
int set_bit;
int block_bit;
int set_size;
int block_size;
int assoc;
char trace_file[PATH_MAX];
bool verbose = false;
bool has_set_bit = false;
bool has_block_bit = false;
bool has_assoc = false;
bool has_tracefile = false;
uint64_t glob_ref_cnt = 0;  // to implement LRU replacement policy

typedef struct cache_line {  // 64 bit address space
	uint8_t valid;
	uint8_t dirty;
	int64_t tag;
	uint64_t ref_cnt;   // to implement LRU replacement policy
} cacheline;

void usage(const char *prog);
bool parse_opt(char *argv[], int argc);

cacheline **cache_init(int set, int assoc);
void cache_simulate(cacheline **cache, int set, int assoc);
void cache_destroy(cacheline **cache, int set, int assoc);

uint8_t get_cacheline_valid_bit(cacheline cl);
uint8_t get_cacheline_dirty_bit(cacheline cl);
int64_t get_cacheline_tag(cacheline cl);
uint64_t get_cacheline_ref_cnt(cacheline cl);
void set_cacheline_valid(cacheline *cl, int8_t valid);
void set_cacheline_dirty(cacheline *cl, int8_t dirty);
void set_cacheline_tag(cacheline *cl, int64_t tag);
void set_cacheline_ref_cnt(cacheline *cl, uint64_t ref_cnt);
void up_cacheline_ref_cnt(cacheline *cl);
bool is_cacheline_valid(cacheline cl);
bool is_cacheline_dirty(cacheline cl);
bool is_cacheline_match_tag(cacheline cl, int64_t tag);
cacheline *find_empty_cacheline_in_set(cacheline *cl_in_set, int assoc);
cacheline *check_cacheline_in_set_hit(cacheline *cl_in_set, int assoc, int64_t tag);
cacheline *find_lru_cacheline_in_set(cacheline *cl_in_set, int assoc);

int main(int argc, char *argv[]){
    bool success = parse_opt(argv, argc);
    if(!success){
    	usage(argv[0]);
	exit(1);
    }

    set_size = 1 << set_bit;
    block_size = 1 << block_bit;

    cacheline **cache = cache_init(set_size, assoc);
    if(!cache){
    	printf("malloc cache failed!\n");
	exit(2);
    }
    
    cache_simulate(cache, set_size, assoc);

    printSummary(hit_cnt, miss_cnt, eviction_cnt);

    cache_destroy(cache, set_size, assoc);
    return 0;
}

void usage(const char *prog){
	printf("Usage: %s [-hv] -s <num> -E <num> -b <num> -t <file>\n", prog);
	printf("Options:\n");
	printf("  -h         Print this help message.\n");
	printf("  -v         Optional verbose flag.\n");
	printf("  -s <num>   Number of set index bits.\n");
	printf("  -E <num>   Number of lines per set.\n");
	printf("  -b <num>   Number of block offset bits.\n");
	printf("  -t <file>  Trace file.\n");
	printf("\n");
	printf("Examples:\n");
	printf("  linux>  ./csim-ref -s 4 -E 1 -b 4 -t traces/yi.trace\n");
	printf("  linux>  ./csim-ref -v -s 8 -E 2 -b 4 -t traces/yi.trace\n");
}

bool parse_opt(char *argv[], int argc){
	if(argc == 1){
		printf("%s: Missing required command line argument\n", argv[0]);
		return false;
	}

	size_t trace_file_len;
	int opt;
	while((opt = getopt(argc, argv, "hvs:E:b:t:")) != -1){
		switch(opt){
		    case 'v':
			verbose = true;
			break;

		    case 's':
			has_set_bit = true;
			set_bit = atoi(optarg);
			break;

		    case 'E':
			has_assoc = true;
			assoc = atoi(optarg);
			break;

		    case 'b':
			has_block_bit = true;
			block_bit = strtol(optarg, NULL, 10);
			break;

		    case 't':
			has_tracefile = true;
			trace_file_len = strlen(optarg);
			assert(trace_file_len < PATH_MAX);
			strncpy(trace_file, optarg, trace_file_len);
			break;

		    case 'h':
			return false;

		    default:
			return false;
		}
	}

	if(!has_tracefile || !has_block_bit || !has_set_bit || !has_assoc)
		return false;

	return true;
}

cacheline **cache_init(int set, int assoc){
	cacheline **cache = NULL;
	
	cache = malloc(sizeof(cacheline *) * set);      // may be unsigned integer overflow, be careful!
	if(!cache)
		return NULL;

	void *ptr;
	int i, j;
	for(i = 0; i < set; i++){
		ptr = malloc(sizeof(cacheline) * assoc);  // also may be unsigned integer overflow, be careful!
		if(!ptr){
			for(j = 0; j < i; j++){
				free(cache[j]);
			}
			free(cache);
			return NULL;
		}
		
		cache[i] = ptr;

		for(j = 0; j < assoc; j++){
			cache[i][j].valid = false;
			cache[i][j].dirty = false;
			cache[i][j].tag = 0;
			cache[i][j].ref_cnt = 0;
		}
	}

	return cache;
}

void cache_destroy(cacheline **cache, int set, int assoc){
	if(!cache)
		return;

	for(int i = 0; i < set; i++){
		free(cache[i]);
	}

	free(cache);
}


void cache_simulate(cacheline **cache, int set, int assoc){
	FILE *trace_file_ptr = fopen(trace_file, "r");
	
	if(!trace_file_ptr){
		printf("cannot open %s\n", trace_file);
		exit(3);
	}

	char operation;
	int64_t addr;
	int64_t addr_len;

	int64_t set_idx;
	int64_t tag;
	//int64_t byte_offset;  // do not need here since we do not store any data in fact

	while(fscanf(trace_file_ptr, " %c %lx,%lu", &operation, &addr, &addr_len) != EOF){
		//byte_offset = addr % block_size;
		set_idx = (addr / block_size) % set_size;
		tag = addr >> (set_bit + block_bit);
		cacheline *empty_cacheline;
		cacheline *hit_cacheline;
		cacheline *lru_cacheline;

		glob_ref_cnt++;

		switch(operation){
			case 'L':
				if((hit_cacheline = check_cacheline_in_set_hit(cache[set_idx], assoc, tag))){
					hit_cnt++;
					set_cacheline_ref_cnt(hit_cacheline, glob_ref_cnt);

					if(verbose)
						printf("%c %lx,%lu hit\n", operation, addr, addr_len);

					continue;
				}
				
				goto load_store_common;

			case 'S':
				if((hit_cacheline = check_cacheline_in_set_hit(cache[set_idx], assoc, tag)) != NULL){
					hit_cnt++;
					set_cacheline_dirty(hit_cacheline, DIRTY);
					set_cacheline_ref_cnt(hit_cacheline, glob_ref_cnt);

					if(verbose)
						printf("%c %lx,%lu hit\n", operation, addr, addr_len);

					continue;
				}

load_store_common:
				if((empty_cacheline = find_empty_cacheline_in_set(cache[set_idx], assoc)) == NULL){
					eviction_cnt++;
					miss_cnt++;

					lru_cacheline = find_lru_cacheline_in_set(cache[set_idx], assoc);
					assert(lru_cacheline != NULL);

					if(is_cacheline_dirty(*lru_cacheline)){ // write back here if neccessary
						set_cacheline_dirty(lru_cacheline, !DIRTY);
					}

					set_cacheline_tag(lru_cacheline, tag);
					set_cacheline_valid(lru_cacheline, VALID);
					set_cacheline_ref_cnt(lru_cacheline, glob_ref_cnt);

					if(verbose)
						printf("%c %lx,%lu miss eviction\n", operation, addr, addr_len);

					continue;
				}

				miss_cnt++;
				set_cacheline_tag(empty_cacheline, tag);
				set_cacheline_valid(empty_cacheline, VALID);
				set_cacheline_ref_cnt(empty_cacheline, glob_ref_cnt);

				if(verbose)
					printf("%c %lx,%lu miss\n", operation, addr, addr_len);

				break;

			case 'M':
				if((hit_cacheline = check_cacheline_in_set_hit(cache[set_idx], assoc, tag)) != NULL){
					hit_cnt += 2;
					set_cacheline_dirty(hit_cacheline, DIRTY);
					set_cacheline_ref_cnt(hit_cacheline, glob_ref_cnt);

					if(verbose)
						printf("%c %lx,%lu hit hit\n", operation, addr, addr_len);

					continue;
				}

				if((empty_cacheline = find_empty_cacheline_in_set(cache[set_idx], assoc)) == NULL){
					eviction_cnt++;
					miss_cnt++;
					hit_cnt++;

					lru_cacheline = find_lru_cacheline_in_set(cache[set_idx], assoc);
					assert(lru_cacheline != NULL);

					if(is_cacheline_dirty(*lru_cacheline)){ // write back here if neccessary
						set_cacheline_dirty(lru_cacheline, !DIRTY);
					}

					set_cacheline_tag(lru_cacheline, tag);
					set_cacheline_valid(lru_cacheline, VALID);
					set_cacheline_ref_cnt(lru_cacheline, glob_ref_cnt);

					if(verbose)
						printf("%c %lx,%lu miss eviction hit\n", operation, addr, addr_len);

					continue;
				}

				miss_cnt++;
				hit_cnt++;
				set_cacheline_tag(empty_cacheline, tag);
				set_cacheline_valid(empty_cacheline, VALID);
				set_cacheline_ref_cnt(empty_cacheline, glob_ref_cnt);

				if(verbose)
					printf("%c %lx,%lu miss hit\n", operation, addr, addr_len);

				break;

			default:
				break;
		}

	}

	fclose(trace_file_ptr);
}

uint8_t get_cacheline_valid_bit(cacheline cl){
	return cl.valid;
	//return (cl.val >> 63) & 0x1;
}

uint8_t get_cacheline_dirty_bit(cacheline cl){
	return cl.dirty;
	//return (cl.val >> 62) & 0x1;
}

void set_cacheline_valid(cacheline *cl, int8_t valid){
	cl->valid = valid;
}

void set_cacheline_dirty(cacheline *cl, int8_t dirty){
	cl->dirty = dirty;
}

void set_cacheline_tag(cacheline *cl, int64_t tag){
	cl->tag = tag;
}

void up_cacheline_ref_cnt(cacheline *cl){
	cl->ref_cnt++;
}

void set_cacheline_ref_cnt(cacheline *cl, uint64_t ref_cnt){
	cl->ref_cnt = ref_cnt;
}

int64_t get_cacheline_tag(cacheline cl){
	return cl.tag;
}

uint64_t get_cacheline_ref_cnt(cacheline cl){
	return cl.ref_cnt;
}

bool is_cacheline_valid(cacheline cl){
	return get_cacheline_valid_bit(cl) == 1 ? true : false;
}

bool is_cacheline_dirty(cacheline cl){
	return get_cacheline_dirty_bit(cl) == 1 ? true : false;
}

bool is_cacheline_match_tag(cacheline cl, int64_t tag){
	return cl.tag == tag ? true : false;
}

cacheline *find_empty_cacheline_in_set(cacheline *cl_in_set, int assoc){
	for(int i = 0; i < assoc; i++){
		if(!is_cacheline_valid(cl_in_set[i])){
			return (cl_in_set + i);
		}
	}

	return NULL;
}

cacheline *check_cacheline_in_set_hit(cacheline *cl_in_set, int assoc, int64_t tag){
	for(int i = 0; i < assoc; i++){
		if(is_cacheline_valid(cl_in_set[i]) && 
		   is_cacheline_match_tag(cl_in_set[i], tag)){
			return (cl_in_set + i);
		}
	}

	return NULL;
}

cacheline *find_lru_cacheline_in_set(cacheline *cl_in_set, int assoc){
	cacheline *lru_cacheline;
	uint64_t least_ref_cnt;
	uint64_t curr_least_ref_cnt;

	least_ref_cnt = cl_in_set[0].ref_cnt;
	for(int i = 1; i < assoc; i++){
		curr_least_ref_cnt = cl_in_set[i].ref_cnt;

		if(curr_least_ref_cnt < least_ref_cnt){
			least_ref_cnt = curr_least_ref_cnt;
			lru_cacheline = cl_in_set + i;
		}
	}

	return lru_cacheline;
}
