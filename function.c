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

#include <stdlib.h>

#include "function.h"
#include "datastructs.h"

function* init_function (function* to_init, unsigned int start_addr)
{
	to_init->start_addr = start_addr;
	next_flags = 0;

	//The following is code meant for the spider disassembler (currently inoperational)
	//See spider.c
	jump_block* root;
	jump_block* current;
	jump_block* temp;

	root = init_jump_block (malloc (sizeof (jump_block)), start_addr);
	current = root;

	//Find all jump blocks
	while (num_push_ebp != 2)
	{
		temp = init_jump_block (malloc (sizeof (jump_block)), current->end);
		link (current, temp);
		current = current->next;
	}
	num_push_ebp = 0;

	//Get jump addresses
	to_init->num_jump_addrs = 0;
	to_init->jump_addrs_buf_size = 8 * sizeof (unsigned int);
	to_init->jump_addrs = malloc (to_init->jump_addrs_buf_size);
	to_init->orig_addrs = malloc (to_init->jump_addrs_buf_size);
	list_loop (resolve_jumps, root, root, to_init);

	//Memory management for "}" placement algorithms
	to_init->num_dups = 0;
	to_init->dup_targets_buf_size = 8 * sizeof (unsigned int);
	to_init->dup_targets = malloc (to_init->dup_targets_buf_size);
	to_init->else_starts = malloc (to_init->dup_targets_buf_size);
	to_init->pivots = malloc (to_init->dup_targets_buf_size);

	//Split jump blocks 
	struct search_params params;
	int i;

	for (i = 0; i < to_init->num_jump_addrs; i ++)
	{
		current = NULL;
		params.ret = (void**)&current;
		params.key = to_init->jump_addrs [i];
		list_loop (search_start_addrs, root, root, params);
	
		if (!current)
		{
			printf ("Error: invalid jump instruction at %p\n", to_init->orig_addrs [i]);
			exit (1);
		}
	
		split_jump_blocks (current, params.key);
	}

	to_init->jump_block_list = root;
	return to_init;
}

void resolve_jumps (jump_block* to_resolve, function* benefactor)
{
	int addr_temp;
	if (to_resolve->instructions [to_resolve->num_instructions-1].mnemonic [0] == 'j')
	{
		benefactor->num_jump_addrs ++;

		if (benefactor->num_jump_addrs * sizeof (unsigned int) > benefactor->jump_addrs_buf_size)
		{
			benefactor->jump_addrs_buf_size *= 2;
			benefactor->jump_addrs = realloc (benefactor->jump_addrs, benefactor->jump_addrs_buf_size);
			benefactor->orig_addrs = realloc (benefactor->orig_addrs, benefactor->jump_addrs_buf_size);
			
		}

		benefactor->jump_addrs [benefactor->num_jump_addrs-1] = relative_insn (&(to_resolve->instructions [to_resolve->num_instructions-1]), to_resolve->end);
		benefactor->orig_addrs [benefactor->num_jump_addrs-1] = index_to_addr (to_resolve->instructions [to_resolve->num_instructions-1].addr);
	}
}

void splice_jump_blocks (jump_block* to_splice, struct splice_params arg)
{
	int i = 0;
	//Copy target data into destination jump block until instruction index hits an unconditional jump
	while (!(to_splice->instructions [i].mnemonic [0] == 'j' && to_splice->instructions [i].mnemonic [1] == 'm' && to_splice->instructions [i].mnemonic [2] == 'p'))
	{
		arg.to_form->instructions [*arg.instruction_index] = to_splice->instructions [i];
		if (to_splice->instructions [i].mnemonic [0] == 'r' && to_splice->instructions [i].mnemonic [1] == 'e' && to_splice->instructions [i].mnemonic [2] == 't')
			break;
		i ++;
		*arg.instruction_index += 1;
	}

	//Include jump instruction if it's part of in function control flow, like a loop
	if (to_splice->flags & IS_LOOP)
	{
		arg.to_form->instructions [*arg.instruction_index] = to_splice->instructions [i];
		*arg.instruction_index += 1;
	}
	else if (to_splice->instructions [i].mnemonic [0] == 'j')
		free (to_splice->instructions [i].operands); //Cleanup operands since this instruction will be completely forgotten

	//Copy conditional jump data into target jump block
	for (i = 0; i < to_splice->num_conditional_jumps; i++)
	{
		arg.to_form->conditional_jumps [*arg.cond_jump_index] = to_splice->conditional_jumps [i];
		*arg.cond_jump_index += 1;
	}

	//Copy call data into target jump block
	for (i = 0; i < to_splice->num_calls; i++)
	{
		arg.to_form->calls [*arg.calls_index] = to_splice->calls [i];
		*arg.calls_index += 1;
	}
}

//Cleanup dynamically allocated memory of a function
void cleanup_function (function* to_cleanup, char scrub_insn)
{
	free (to_cleanup->jump_addrs);
	free (to_cleanup->orig_addrs);
	jump_block_list_cleanup (to_cleanup->jump_block_list, scrub_insn);
}

//Properly free memory used in a function list
void function_list_cleanup (function* to_cleanup, char scrub_insn)
{
	list_cleanup (to_cleanup, cleanup_function, scrub_insn);
}

//Search function start addresses to look for repetition so we don't add the same function multiple times
void search_func_start_addrs (function* to_test, struct search_params arg)
{
	if (to_test->start_addr == arg.key)
		*arg.ret = (void**)1;
}

//Helper function for resolve calls (callback for list_loop)
void resolve_calls_help (jump_block* benefactor, function* parent)
{
	struct search_params arg;
	int i = 0;
	char ret = 0;
	arg.ret = (void**)&ret;
	function* to_link;

	for (i; i < benefactor->num_calls; i ++)
	{
		arg.key = benefactor->calls [i];
		list_loop (search_func_start_addrs, parent, parent, arg);
		if (!ret) //Redundancy check; don't add the same function multiple times
		{
			if (benefactor->calls [i] < text_addr) //Likely a reference to plt, data isn't in this file so don't bother
				continue;
			if (addr_to_index (benefactor->calls [i]) >= file_size) //Critical error: should not call outside of address space
				continue;
			to_link = init_function (malloc (sizeof (function)), benefactor->calls [i]);
			link (parent, to_link);
		}
	}
}

//Find every function call in every function and add that function to the list
void resolve_calls (function* benefactor)
{
	function* start = benefactor;

	//list_loop is already a macro, can't pass a macro to a macro like you could a function
	do
	{
		list_loop (resolve_calls_help, benefactor->jump_block_list, benefactor->jump_block_list, benefactor);
		benefactor = benefactor->next;
	} while (benefactor != start && benefactor);
}

void split_jump_blocks (jump_block* to_split, unsigned int addr)
{
	if (to_split->start == addr)
		return;
	jump_block* new_block;
	int i = 0;
	int j;
	x86_oplist_t* next;
	unsigned int flags = to_split->flags;
	x86_insn_t* split_instruction;
	while (index_to_addr (to_split->instructions [i].addr) != addr)
		i ++;

	new_block = init_jump_block (malloc (sizeof (jump_block)), index_to_addr (to_split->instructions [i].addr));

	for (j = i; j < to_split->num_instructions; j++)
	{
		while (to_split->instructions [j].operands && to_split->instructions [j].operands->next)
		{
			next = to_split->instructions [j].operands->next;
			free (to_split->instructions [j].operands);
			to_split->instructions [j].operands = next;
		}
		free (to_split->instructions [j].operands);
		to_split->instructions [j].operands = NULL;
	}
	
	to_split->num_instructions = i;
	to_split->end = new_block->start;

	new_block->flags = flags & (IS_LOOP | IS_CONTINUE | IS_BREAK | IS_GOTO);
	to_split->flags = flags & (IS_ELSE | IS_IF | IS_AFTER_ELSE | IS_IF_TARGET | IS_AFTER_LOOP);

	link (to_split, new_block);
}
