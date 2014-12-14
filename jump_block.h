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


#include <stddef.h>
#include <libdis.h>

#include "elf_parser.h"

#pragma once

#define IS_LOOP 1
#define IS_ELSE 2
#define IS_IF 4
#define IS_IF_TARGET 8
#define IS_AFTER_ELSE 16
#define IS_AFTER_LOOP 32
#define IS_CONTINUE 64
#define IS_BREAK 128
#define IS_GOTO 256
#define IS_WHILE 512
#define NO_TRANSLATE 1024

unsigned int next_flags;
extern char num_push_ebp;

struct jump_block
{
	unsigned int flags;
	unsigned int start;
	unsigned int end;
	x86_insn_t* instructions; //Array of instructions contained in jump block in human readable format
	int num_instructions;
	size_t instructions_buf_size;
	unsigned int* conditional_jumps; //Target addresses of all conditional jumps in block
	int num_conditional_jumps;
	size_t conditional_jumps_buf_size;
	unsigned int* calls; //Target addresses of all additional calls in block
	int num_calls;
	size_t calls_buf_size;
	struct jump_block* next;
};
typedef struct jump_block jump_block;

struct search_params //Throwaway parameter structure for searching through start addresses for a start address "key"
{
	void** ret;
	unsigned int key;
};

jump_block* init_jump_block (jump_block* to_init, unsigned int start_addr);
void cleanup_jump_block (jump_block* to_cleanup, char scrub_insn);
void jump_block_list_cleanup (jump_block* to_cleanup, char scrub_insn);
void search_start_addrs (jump_block* to_test, struct search_params arg);
void resolve_conditional_jumps (jump_block* benefactor);
void print_jump_block (jump_block* to_print);
void print_jump_block_list (jump_block* to_print);
x86_insn_t* get_insn_by_addr (jump_block* parent, unsigned int addr);
unsigned int relative_insn (x86_insn_t* insn, unsigned int address);
void cleanup_instruction_list (jump_block* to_cleanup, char scrub_insn);
void parse_instructions (jump_block* to_parse);
