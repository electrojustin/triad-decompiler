#include "jump_block.h"

#pragma once

struct function
{
	struct function* next;
	jump_block* jump_block_list;
	unsigned int* jump_addrs;
	unsigned int* orig_addrs;
	unsigned int* dup_targets;
	unsigned int* else_starts;
	unsigned int* pivots;
	int num_dups;
	size_t dup_targets_buf_size;
	size_t jump_addrs_buf_size;
	int num_jump_addrs;
	unsigned int start_addr;
	unsigned int stop_addr;
};
typedef struct function function;

function* entry_func;

struct splice_params //Throwaway parameter structure for splicing together various jump blocks into "to_form"
{
	jump_block* to_form;
	int* instruction_index;
	int* cond_jump_index;
	int* calls_index;
};

function* init_function (function* to_init, unsigned int start_addr, unsigned int stop_addr);
void split_jump_blocks (jump_block* to_split, unsigned int addr, unsigned int stop_addr);
void resolve_calls_help (jump_block* benefactor, function* parent);
void resolve_calls (function* benefactor);
void cleanup_function (function* to_cleanup, char scrub_insn);
void function_list_cleanup (function* to_cleanup, char scrub_insn);
void search_func_start_addrs (function* to_test, struct search_params arg);
void resolve_jumps (jump_block* to_resolve, function* benefactor);
