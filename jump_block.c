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

#include <string.h>
#include <stdlib.h>
#include <libdis.h>

#include "program.h"
#include "jump_block.h"
#include "datastructs.h"

char num_push_ebp = 0;

jump_block* init_jump_block (jump_block* to_init, unsigned int start_addr, char* block, char is_spider)
{
	to_init->instructions = NULL;
	to_init->calls = NULL;
	to_init->conditional_jumps = NULL;
	to_init->flags = next_flags;
	next_flags = 0;
	to_init->next = NULL;

	//Locals to cut down on dereference operators; this code was a disaster the first time around with no locals
	int size;
	int num_instructions = 0;
	int num_calls = 0;
	int num_conditional_jumps = 0;
	unsigned int current = start_addr;
	unsigned int next_addr;
	x86_insn_t instruction;

	to_init->start = start_addr;

	do
	{
		num_instructions ++;

		//Dynamic memory allocation stuff here
		if (num_instructions - 1)
		{
			if (num_instructions * sizeof (x86_insn_t) > to_init->instructions_buf_size)
			{
				to_init->instructions_buf_size *= 2; //Just double the buffer; I'd rather allocate too much than reallocate memory every single iteration
				to_init->instructions = realloc (to_init->instructions, to_init->instructions_buf_size);
			}
		}
		else
		{
			to_init->instructions_buf_size = 256 * sizeof (x86_insn_t); //My memory allocator screams at me for numbers that aren't a multiple of 8
			to_init->instructions = malloc (to_init->instructions_buf_size);
		}

		//Partially disassemble the instruction into machine readable format
		size = x86_disasm (block, file_size, 0, addr_to_index (current), &instruction);
		to_init->instructions [num_instructions-1] = instruction;
		current += size;

		//Identify references to conditional jump blocks and function calls for later disassembly.
		if (instruction.operands && instruction.operands->op.datatype < 6) //Please don't go chasing rax...
		{
			if (is_spider)
			{
				//Keep track of conditional jumps
				if (instruction.mnemonic [0] == 'j' && instruction.mnemonic [1] != 'm')
				{
					num_conditional_jumps ++;

					//Dynamic memory allocation stuff here
					if (num_conditional_jumps - 1)
					{
						if (num_conditional_jumps * sizeof (unsigned int) > to_init->conditional_jumps_buf_size)
						{
							to_init->conditional_jumps_buf_size *= 2;
							to_init->conditional_jumps = realloc (to_init->conditional_jumps, 2 * to_init->conditional_jumps_buf_size);
						}
					}
					else
					{
						to_init->conditional_jumps_buf_size = 8 * sizeof (unsigned int);
						to_init->conditional_jumps = malloc (to_init->conditional_jumps_buf_size);
					}

					//Add operand address to conditional jump buffer
					to_init->conditional_jumps [num_conditional_jumps-1] = relative_insn (&instruction, current);
				}
			}

			//Keep track of calls
			if (instruction.mnemonic [0] == 'c' && instruction.mnemonic [1] == 'a')
			{
				num_calls ++;

				//More dynamic memory allocation stuff here
				if (num_calls - 1)
				{
					if (num_calls * sizeof (unsigned int) > to_init->calls_buf_size)
					{
						to_init->calls_buf_size *= 2;
						to_init->calls = realloc (to_init->calls, to_init->calls_buf_size);
					}
				}
				else
				{
					to_init->calls_buf_size = 8 * sizeof (unsigned int);
					to_init->calls = malloc (to_init->calls_buf_size);
				}

				//Add operand address to call buffer 
				to_init->calls [num_calls-1] = relative_insn (&instruction, current);
			}

			//Keep track of how many times we've seen the instruction "push %ebp". One too many and we've started on the adjacent function.
			if (instruction.type == insn_push && !strcmp (instruction.operands->op.data.reg.name, "ebp"))
				num_push_ebp ++;
			if (instruction.addr > file_size)
				num_push_ebp = 2;
		}
		//Stop disassembly of jump block at next unconditional jump or call
	} while (!(instruction.mnemonic [0] == 'j' && (instruction.mnemonic [1] == 'm' || !is_spider)) && num_push_ebp != 2); //Jump block ends on jump or return

	//Synchronize the jump block with locals
	to_init->end = current;
	to_init->num_conditional_jumps = num_conditional_jumps;
	to_init->num_calls = num_calls;
	to_init->num_instructions = num_instructions;
	if (instruction.type == insn_jcc)
	{
		if (relative_insn (&instruction, current) < current-size)
		{
			to_init->flags |= IS_LOOP;
			next_flags |= IS_AFTER_LOOP;
		}
	}

	//Print jump block start address; uncomment for debugging information
	//printf ("%p\n", to_init->start);

	return to_init; //Convenient to return the to_init param so we can chain function calls like "example (init_jump_block (malloc (sizeof (jump_block)), some_addr, block))"
}

void cleanup_jump_block (jump_block* to_cleanup, char scrub_insn)
{
	if (to_cleanup->num_conditional_jumps)
		free (to_cleanup->conditional_jumps);
	if (to_cleanup->num_calls)
		free (to_cleanup->calls);

	//Additional cleanup needed for instructions because operands are a dynamically allocated linked list
	if (scrub_insn)
	{
		int i = 0;
		x86_oplist_t* next;
		for (i; i < to_cleanup->num_instructions; i ++)
		{
			while (to_cleanup->instructions [i].operands && to_cleanup->instructions [i].operands->next)
			{
				next = to_cleanup->instructions [i].operands->next;
				free (to_cleanup->instructions [i].operands);
				to_cleanup->instructions [i].operands = next;
			}
			free (to_cleanup->instructions [i].operands);
		}
	}

	//Now it's ok to just free the instructions buffer
	if (to_cleanup->num_instructions)
		free (to_cleanup->instructions);
}

//Free a list of jump blocks properly
void jump_block_list_cleanup (jump_block* to_cleanup, char scrub_insn)
{
	list_cleanup (to_cleanup, cleanup_jump_block, scrub_insn);
}

//Callback function used for cross checking a potential jump block start addresses against existing jump block address ranges
void search_start_addrs (jump_block* to_test, struct search_params arg)
{
	if (to_test->start <= arg.key && to_test->end > arg.key)
		*arg.ret = to_test;
}

//Add conditional jumps to the list of jumps
void resolve_conditional_jumps (jump_block* benefactor)
{
	int i = 0;
	jump_block* ret;
	struct search_params arg;
	arg.ret = (void**)&ret;
	jump_block* to_link;
	for (i; i < benefactor->num_conditional_jumps; i ++)
	{
		arg.key = benefactor->conditional_jumps [i];
		ret = NULL;
		list_loop (search_start_addrs, benefactor, benefactor, arg);
		if (!ret && benefactor->conditional_jumps [i] >= text_addr) //Redundancy and sanity check; don't add the same block multiple times and don't start disassembling plt
		{
			to_link = init_jump_block (malloc (sizeof (jump_block)), benefactor->conditional_jumps [i], file_buf, 1);
			link (benefactor, to_link);
		}
	}
}

//Print the dissassembly of the given jump block
void print_jump_block (jump_block* to_print)
{
	int i;
	char line [100];
	printf ("jump block %p:\n", to_print->start);
	for (i = 0; i < to_print->num_instructions; i ++)
	{
		x86_format_insn (&(to_print->instructions [i]), line, 100, att_syntax);
		printf ("%s\n", line);
	}
	printf ("\n");
}

//Go through entire jump block list and print out the jump blocks individually
void print_jump_block_list (jump_block* to_print)
{
	list_loop (print_jump_block, to_print, to_print);
}

x86_insn_t* get_insn_by_addr (jump_block* parent, unsigned int addr)
{
	int i;

	for (i = 0; i < parent->num_instructions; i ++)
	{
		if (index_to_addr (parent->instructions [i].addr) == addr)
			return &(parent->instructions [i]);
	}
	return NULL;
}

//Processes relative instructions
unsigned int relative_insn (x86_insn_t* insn, unsigned int address)
{
	if (insn->operands->op.type != op_absolute)
	{
		int ret;
		if (insn->operands->op.datatype == op_dword)
			ret = (signed int)insn->operands->op.data.dword;
		else if (insn->operands->op.datatype == op_word)
			ret = (signed short)insn->operands->op.data.word;
		else //op_byte, or at least it should be
			ret = (signed char)insn->operands->op.data.byte;
		return address+ret;
	}
	else
		return insn->operands->op.data.dword;
}
