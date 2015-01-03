#include <string.h>
#include <stdlib.h>
#include <libdis.h>

#include "jump_block.h"
#include "datastructs.h"

char num_push_ebp = 0;

jump_block* init_jump_block (jump_block* to_init, unsigned int start_addr)
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
		size = x86_disasm (file_buf, file_size, 0, addr_to_index (current), &instruction);
		to_init->instructions [num_instructions-1] = instruction;
		current += size;

		//Identify references to conditional jump blocks and function calls for later disassembly.
		if (instruction.operands && instruction.operands->op.datatype < 6) //Please don't go chasing rax...
		{
			//Keep track of calls
			if (instruction.type == insn_call)
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
		}
		//Keep track of how many times we've seen the instruction "push %ebp". One too many and we've started on the adjacent function.
		if (instruction.type == insn_push && !strcmp (instruction.operands->op.data.reg.name, "ebp"))
			num_push_ebp ++;
		if (instruction.addr > file_size) //If we're outside the text section, we should be done.
			num_push_ebp = 2;
	//Stop disassembly of jump block at next unconditional jump or call
	} while (instruction.mnemonic [0] != 'j' && num_push_ebp != 2); //Jump block ends on jump or return

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
