/*Copyright (C) 2014 Justin Green
  SHA512 sum of resume: ee1dcaa00b931696d73f0d978e39ac2c8302de27a5034b7035bd9111d1f48ddf9fae46842baa3af2a56f17f8043cdd5760ced014c223a13fab1ad29cbfb3748c
  How to use this checksum: open up directory with my resume and type "sha512sum resume.docx" into the bash prompt.
  Then compare the two checksums.

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.*/

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

function* init_function (function* to_init, unsigned int start_addr, char* block, char is_spider);
void splice_jump_blocks (jump_block* to_splice, struct splice_params arg);
void split_jump_blocks (jump_block* to_split, unsigned int addr);
void resolve_calls_help (jump_block* benefactor, function* parent);
void resolve_calls (function* benefactor);
void cleanup_function (function* to_cleanup, char scrub_insn);
void function_list_cleanup (function* to_cleanup, char scrub_insn);
void search_func_start_addrs (function* to_test, struct search_params arg);
void print_function (function* to_print);
void print_function_list (function* to_print);
void resolve_jumps (jump_block* to_resolve, function* benefactor);