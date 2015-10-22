#include <string.h>
#include <stdlib.h>
#include <capstone/capstone.h>

#include "jump_block.h"
#include "datastructs.h"

char num_push_ebp = 0;

jump_block* init_jump_block (jump_block* to_init, unsigned int start_addr, unsigned int stop_addr)
{
	to_init->instructions = NULL;
	to_init->calls = NULL;
	to_init->conditional_jumps = NULL;
	to_init->flags = next_flags;
	next_flags = 0;
	to_init->next = NULL;

	//Locals to cut down on dereference operators; this code was a disaster the first time around with no locals
	size_t size = file_size;
	int num_instructions = 0;
	int num_calls = 0;
	int num_conditional_jumps = 0;
	unsigned long long relative_address = 0;
	unsigned int current_addr = start_addr;
	uint8_t* current = file_buf + addr_to_index (current_addr);
	unsigned int next_addr;
	cs_insn* instruction = cs_malloc (handle);

	to_init->start = start_addr;

	do
	{
		num_instructions ++;

		//Dynamic memory allocation stuff here
		if (num_instructions - 1)
		{
			if (num_instructions * sizeof (cs_insn) > to_init->instructions_buf_size)
			{
				to_init->instructions_buf_size *= 2; //Just double the buffer; I'd rather allocate too much than reallocate memory every single iteration
				to_init->instructions = (cs_insn*)realloc (to_init->instructions, to_init->instructions_buf_size);
			}
		}
		else
		{
			to_init->instructions_buf_size = 256 * sizeof (cs_insn); //My memory allocator screams at me for numbers that aren't a multiple of 8
			to_init->instructions = (cs_insn*)malloc (to_init->instructions_buf_size);
		}

		//Partially disassemble the instruction into machine readable format
		cs_disasm_iter (handle, (const uint8_t **)&current, &file_size, (uint64_t*)&relative_address, instruction);
		to_init->instructions [num_instructions-1] = *instruction;
		to_init->instructions [num_instructions-1].detail = (cs_detail*)malloc (sizeof(cs_detail));
		*(to_init->instructions [num_instructions-1].detail) = *(instruction->detail);
		current_addr = index_to_addr ((char*)current - file_buf);

		//Identify references to conditional jump blocks and function calls for later disassembly.
		if (instruction->detail->x86.op_count && instruction->detail->x86.operands [0].type > X86_OP_REG) //Please don't go chasing rax...
		{
			//Keep track of calls
			if (instruction->id == X86_INS_CALL)
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
				to_init->calls [num_calls-1] = relative_insn (instruction, current_addr);
			}
		}
		//Keep track of how many times we've seen the instruction "push %ebp". One too many and we've started on the adjacent function.
		if ((instruction->id >= X86_INS_PUSH && instruction->id <= X86_INS_PUSHFQ) && (instruction->detail->x86.operands [0].reg == X86_REG_EBP || instruction->detail->x86.operands [0].reg == X86_REG_RBP))
			num_push_ebp ++;
		if (current_addr > stop_addr) //If we're outside the text section, we should be done.
			num_push_ebp = 2;
	//Stop disassembly of jump block at next unconditional jump or call
	} while (instruction->mnemonic [0] != 'j' && num_push_ebp != 2); //Jump block ends on jump or return

	//Synchronize the newly created jump block datastructure fields with locals
	to_init->end = current_addr;
	to_init->num_conditional_jumps = num_conditional_jumps;
	to_init->num_calls = num_calls;
	to_init->num_instructions = num_instructions;
	if (instruction->id >= X86_INS_JAE && instruction->id <= X86_INS_JS && instruction->id != X86_INS_JMP)
	{
		if (relative_insn (instruction, current_addr) < current_addr - instruction->size)
		{
			to_init->flags |= IS_LOOP;
			next_flags |= IS_AFTER_LOOP;
		}
	}

	cs_free (instruction, 1);

	//Print jump block start address; uncomment for debugging information
	//printf ("%p\n", to_init->start);

	return to_init; //Convenient to return the to_init param so we can chain function calls like "example (init_jump_block (malloc (sizeof (jump_block)), some_addr, block))"
}

//Function parsing needs all of the instructions, and translating into C needs all of the instructions, but storing all of the instructions between those two points in time
//takes up an enourmous amount of memory. So we need a seperate function from the init function to disassemble all of the instructions in a jump block a second time.
void parse_instructions (jump_block* to_parse)
{
	uint8_t* current = file_buf + addr_to_index (to_parse->start);
	size_t size = to_parse->end - to_parse->start;

	cs_disasm (handle, current, size, 0x0000, 0, &(to_parse->instructions));
}

void cleanup_jump_block (jump_block* to_cleanup, char scrub_insn)
{
	if (to_cleanup->num_conditional_jumps)
		free (to_cleanup->conditional_jumps);
	if (to_cleanup->num_calls)
		free (to_cleanup->calls);

	cleanup_instruction_list (to_cleanup, scrub_insn);
}

void cleanup_instruction_list (jump_block* to_cleanup, char scrub_insn)
{	
	//Additional cleanup needed for instructions because operands are a dynamically allocated linked list
	if (scrub_insn)
		cs_free (to_cleanup->instructions, to_cleanup->num_instructions);

	else if (to_cleanup->num_instructions)
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

cs_insn* get_insn_by_addr (jump_block* parent, unsigned int addr)
{
	int i;

	for (i = 0; i < parent->num_instructions; i ++)
	{
		if (parent->instructions [i].address + parent->start == addr)
			return &(parent->instructions [i]);
	}
	return NULL;
}

//Processes relative instructions
long long relative_insn (cs_insn* insn, unsigned long long address)
{
	if (insn->id == X86_INS_LCALL || insn->id == X86_INS_LJMP)
		return insn->detail->x86.operands [0].imm;
	else
		return insn->detail->x86.operands [0].imm + address - insn->address - insn->size;
}
