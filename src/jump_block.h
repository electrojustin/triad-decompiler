#include <stddef.h>
#include <capstone/capstone.h>

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

csh handle;
unsigned int next_flags;
extern char num_push_ebp;

struct jump_block
{
	unsigned int flags;
	unsigned long long start;
	unsigned long long end;
	cs_insn* instructions; //Array of instructions contained in jump block in human readable format
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

jump_block* init_jump_block (jump_block* to_init, unsigned int start_addr, unsigned int stop_addr);
void cleanup_jump_block (jump_block* to_cleanup, char scrub_insn);
void jump_block_list_cleanup (jump_block* to_cleanup, char scrub_insn);
void search_start_addrs (jump_block* to_test, struct search_params arg);
void resolve_conditional_jumps (jump_block* benefactor);
void print_jump_block (jump_block* to_print);
void print_jump_block_list (jump_block* to_print);
cs_insn* get_insn_by_addr (jump_block* parent, unsigned int addr);
long long relative_insn (cs_insn* insn, unsigned long long address);
void cleanup_instruction_list (jump_block* to_cleanup, char scrub_insn);
void parse_instructions (jump_block* to_parse);
