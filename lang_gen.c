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


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libdis.h>

#include "lang_gen.h"
#include "datastructs.h"

char test_conditions [14] [3] = {"<\0\0", ">=\0", "!=\0", "==\0", "<=\0", ">\0\0", "<\0\0", ">\0\0", "\0\0\0", "\0\0\0", "<\0\0", ">=\0", "<=\0", ">\0\0"};

void translate_insn (x86_insn_t instruction, x86_insn_t next_instruction)
{
	char* line = malloc (128);
	char* name = NULL;
	int len;
	int line_length = 128;
	var* temp;
	var* temp2;
	bzero (line, 128);
	int actual_translation_size = strlen (translation);
	int i;
	int target_addr;

	switch (instruction.type)
	{
		//We cut out anything involving EBP or ESP since these are not general purpose registers and would not be part of original program arithmetic
		//insn_mov through insn_xor are just basic arithmetic operators
		case insn_mov:
			temp = add_var (instruction.operands->op);
			temp2 = add_var (instruction.operands->next->op);
			if (strcmp (temp->name, "ebp") && strcmp (temp->name, "esp"))
			{
				if (strcmp (instruction.mnemonic, "lea"))
				{
					if (temp->type != DEREF && temp2->type != DEREF)
						sprintf (line, "%s = %s;\n", temp->name, temp2->name);
					else if (temp->type == DEREF && temp2->type != DEREF)
						sprintf (line, "*(%s*)(%s+(%d)) = %s;\n", temp->c_type, temp->name, temp->loc.disp, temp2->name);
					else if (temp->type != DEREF && temp2->type == DEREF)
						sprintf (line, "%s = *(%s*)(%s+(%d));\n", temp->name, temp2->c_type, temp2->name, temp2->loc.disp);
					else
						sprintf (line, "*(%s*)(%s+(%d)) = *(%s*)(%s+(%d))", temp->c_type, temp->name, temp->loc.disp, temp2->c_type, temp2->name, temp2->loc.disp);
				}
				else
					sprintf (line, "%s = (%s)&%s;\n", temp->name, temp2->c_type, temp2->name);	
			}
			break;
		case insn_sub:
			temp = add_var (instruction.operands->op);
			temp2 = add_var (instruction.operands->next->op);
			if (strcmp (temp->name, "ebp") && strcmp (temp->name, "esp"))
				sprintf (line, "%s -= %s;\n", temp->name, temp2->name);
			break;
		case insn_add:
			temp = add_var (instruction.operands->op);
			temp2 = add_var (instruction.operands->next->op);
			if (strcmp (temp->name, "ebp") && strcmp (temp->name, "esp"))
				sprintf (line, "%s += %s;\n", temp->name, temp2->name);
			break;
		case insn_mul:
			temp = add_var (instruction.operands->op);
			temp2 = add_var (instruction.operands->next->op);
			if (strcmp (temp->name, "ebp") && strcmp (temp->name, "esp"))
				sprintf (line, "%s *= %s;\n", temp->name, temp2->name);
			break;
		case insn_and:
			temp = add_var (instruction.operands->op);
			temp2 = add_var (instruction.operands->next->op);
			if (strcmp (temp->name, "ebp") && strcmp (temp->name, "esp"))
				sprintf (line, "%s &= %s;\n", temp->name, temp2->name);
			break;
		case insn_or:
			temp = add_var (instruction.operands->op);
			temp2 = add_var (instruction.operands->next->op);
			if (strcmp (temp->name, "ebp") && strcmp (temp->name, "esp"))
				sprintf (line, "%s |= %s;\n", temp->name, temp2->name);
			break;
		case insn_xor:
			temp = add_var (instruction.operands->op);
			temp2 = add_var (instruction.operands->next->op);
			if (strcmp (temp->name, "ebp") && strcmp (temp->name, "esp"))
				sprintf (line, "%s ^= %s;\n", temp->name, temp2->name);
			break;
		case insn_pop:
			break;
		case insn_return:
			sprintf (line, "return eax;\n"); //All functions return EAX
			break;
		case insn_leave:
			break;
		case insn_push: //pushing onto the stack is how the caller passes arguments to the the callee
			temp = add_var (instruction.operands->op);
			if (temp->type != REG || (strcmp (temp->name, "ebp") && strcmp (temp->name, "esp") && strcmp (temp->name, "ecx")))
			{
				//Add the variable to the argument array (caller_param). Cannot use argument linked list because the variables used are already linked into the local
				//variable linked list.
				if (!caller_param)
				{
					caller_params_size = 8*sizeof (var);
					caller_param = malloc (caller_params_size);
				}
				num_caller_params ++;
				if (num_caller_params * sizeof (var) > caller_params_size)
				{
					caller_params_size *= 2;
					caller_param = realloc (caller_param, caller_params_size);
				}
				caller_param [num_caller_params-1] = *temp;
				
			}
			break;
		case insn_call:
			target_addr = relative_insn (&instruction, index_to_addr (instruction.addr) + instruction.size);
			if ((unsigned char)file_buf [addr_to_index (target_addr)] == 0xFF && dynamic_string_table)
				name = &(dynamic_string_table [find_reloc_sym (*(int*)&(file_buf [addr_to_index (target_addr)+2]))->st_name]);
			else if (string_hash_table)
				name = string_hash_table [target_addr-0x8048000];
			if (name)
			{
				len = strlen (name);
				if (len + 12 + num_caller_params*22 > line_length)
				{
					line_length = len + 12 + num_caller_params*22;
					line = realloc (line, line_length);
				}
				sprintf (line, "eax = %s (", name);
			}
			else
				sprintf (line, "eax = func_%p (", target_addr);


			//Print the argument list
			if (caller_param)
			{
				sprintf (&(line [strlen (line)]), "%s", caller_param [num_caller_params-1].name);
				for (i = num_caller_params-2; i >= 0; i --)
				{
					if (caller_param [i].type == DEREF)
						sprintf (&(line [strlen (line)]), ", *(%s*)(%s+(%d))", caller_param [i].c_type, caller_param [i].name, caller_param [i].loc.disp);
					else
						sprintf (&(line [strlen (line)]), ", %s", caller_param [i].name);
				}
			}

			sprintf (&(line [strlen (line)]), ");\n");
			free (caller_param);
			caller_param = NULL;
			num_caller_params = 0;
			caller_params_size = 0;
			break;
		case insn_test: //the test instruction is normally found in the context test %eax,%eax. This compares EAX to 0.
			//Instruction after a compare or a test is usually a conditional jump
			target_addr = relative_insn (&next_instruction, index_to_addr (next_instruction.addr) + next_instruction.size); 
			temp = add_var (instruction.operands->op);
			if (target_addr > index_to_addr (next_instruction.addr))
				sprintf (next_line, "\nif (%s %s 0)\n{\n", temp->name, test_conditions [next_instruction.bytes [0] - 0x72]); //The conditional jumps start "jump if below" which has an opcode of 0x72
			else
				sprintf (next_line, "} while (%s %s 0);\n\n", temp->name, test_conditions [next_instruction.bytes [0] - 0x72]);
			break;
		case insn_cmp: //the compare instructions just "compares" its two operands
			temp = add_var (instruction.operands->op);
			temp2 = add_var (instruction.operands->next->op);
			target_addr = relative_insn (&next_instruction, index_to_addr (next_instruction.addr) + next_instruction.size);
			if (target_addr > index_to_addr (next_instruction.addr))
				sprintf (next_line, "\nif (%s %s %s)\n{\n", temp->name, test_conditions [next_instruction.bytes [0] - 0x72], temp2->name);
			else
				sprintf (next_line, "} while (%s %s %s);\n\n", temp->name, test_conditions [next_instruction.bytes [0] - 0x72], temp2->name);
			break;
		case insn_jcc:
			sprintf (line, next_line);
			bzero (next_line, 128);
			break;
		case insn_jmp:
			break;
		case insn_nop:
			break;
		default:
			x86_format_insn (&instruction, line, 128, att_syntax);
			line [strlen (line)] = '\n';
			break;
	}

	//Add the translated line to the final translation
	if (actual_translation_size + strlen (line) > translation_size)
	{
		translation_size = 2*(translation_size + strlen (line));
		translation = realloc (translation, translation_size);
	}
	strcpy (&(translation [actual_translation_size]), line);
	actual_translation_size += strlen (line);
	translation [actual_translation_size] = '\0';

	free (line);
}

//Final translation of each jump block, among other things.
//Also contains some routines that need to be performed per jump block.
//These routines are second iteration routines (see jump_block_preprocessing header)
void translate_jump_block (jump_block* to_translate, function* parent)
{
	int i;
	int j;
	int len;
	unsigned int target = 0;
	unsigned int target2 = 0;

	if (to_translate->instructions [to_translate->num_instructions-1].type == insn_jmp) //Get unconditional jump target address, if possible
	{
		target = to_translate->instructions [to_translate->num_instructions-1].size + index_to_addr (to_translate->instructions [to_translate->num_instructions-1].addr);
		target = relative_insn (&(to_translate->instructions [to_translate->num_instructions-1]), target);
	}
	if (to_translate->instructions [to_translate->num_instructions-1].type == insn_jcc) //Get conditional jump target address, if possible
	{
		target2 = to_translate->instructions [to_translate->num_instructions-1].size + index_to_addr (to_translate->instructions [to_translate->num_instructions-1].addr);
		target2 = relative_insn (&(to_translate->instructions [to_translate->num_instructions-1]), target2);
	}
	unsigned int orig = index_to_addr (to_translate->instructions [to_translate->num_instructions-1].addr); //Get address of last instruction in block

	//Need to print out a "}" at the end of a non-nested IF/ELSE statement, so we need to override the "do not place } at an unconditional jump address" rule.
	if (to_translate->next && target && to_translate->next->flags & IS_ELSE)
		file_buf [to_translate->instructions [to_translate->num_instructions-1].addr] = 0xea;

	//Sets up pivot addresses for "}" placement algorithm.
	//Pivot addresses is the conditional jump of the IF statement associated with the ELSE right before the duplicated target
	if (to_translate->next && to_translate->next->flags & IS_IF)
	{
		for (i = 0; i < parent->num_dups; i ++)
		{
			if (target2 && target2 == parent->else_starts [i])
			{
				parent->pivots [i] = orig;
				break;
			}
			/*else if (target && target == parent->else_starts [i])
			{
				parent->pivots [i] = to_translate->end;
				break;
			}*/
		}
	}

	//"}" placement algorithm
	if (target || target2)
	{
		for (i = 0; i < parent->num_dups; i ++)
		{
			if (target2 && target2 == parent->dup_targets [i])
			{
				//Any jump that comes after the associated if statement, before the else statement, and isn't an unconditional jump immediately before the else 
				//block should be redirected to the start of the else block in order to get the rest of translate_jump_blocks to place the "}" correctly
				if (orig >= parent->pivots [i] && orig < parent->else_starts [i] && parent->pivots [i] && to_translate->end != parent->else_starts [i])
				{
					if (to_translate->next->end != parent->dup_targets [i])
					{
						for (j = 0; j < parent->num_jump_addrs; j++)
						{
							if (parent->jump_addrs [j] == parent->dup_targets [i])
							{
								parent->jump_addrs [j] = parent->else_starts [i];
								break;
							}
						}
					}
				}
				break;
			}
			else if (target && target == parent->dup_targets [i])
			{
				if (orig >= parent->pivots [i] && orig < parent->else_starts [i] && parent->pivots [i] && to_translate->end != parent->else_starts [i])
				{
					if (to_translate->next->end != parent->dup_targets [i])
					{
						for (j = 0; j < parent->num_jump_addrs; j++)
						{
							if (parent->jump_addrs [j] == parent->dup_targets [i])
							{
								parent->jump_addrs [j] = parent->else_starts [i];
								break;
							}
						}
					}
				}
				break;
			}
		}
	}

	for (i = 0; i < parent->num_jump_addrs; i ++)
	{
		if (to_translate->start == parent->jump_addrs [i])
		{
			if (parent->orig_addrs [i])
			{
				if ((unsigned char)(file_buf [addr_to_index (parent->orig_addrs [i])]) != 0xeb) //0xeb is the unconditional jump opcode. Don't put a "}" or a "do" inside of a while loop TODO: this is dumb, find a different way to check jumps
				{
					len = strlen (translation);
					if (to_translate->start > parent->orig_addrs [i])
					{
						if (len + 3 > translation_size)
						{
							translation_size  = 2*(len + 3);
							translation = realloc (translation, translation_size);
						}
						sprintf (&(translation [len]), "}\n\n");
					}
				}
			}	
		}
	}

	for (i = 0; i < parent->num_jump_addrs; i ++)
	{
		if (to_translate->start == parent->jump_addrs [i])
		{
			if (parent->orig_addrs [i])
			{
				if ((unsigned char)(file_buf [addr_to_index (parent->orig_addrs [i])]) != 0xeb) //0xeb is the unconditional jump opcode
				{
					len = strlen (translation);
					if (to_translate->start < parent->orig_addrs [i])
					{
						if (len + 6 > translation_size)
						{
							translation_size  = 2*(len + 6);
							translation = realloc (translation, translation_size);
						}
						sprintf (&(translation [len]), "\ndo\n{\n");
					}
				}
			}
		}
	}

	if (to_translate->flags & IS_ELSE)
	{
		len = strlen (translation);
		if (len + 7 > translation_size)
		{
			translation_size  = 2*(len + 7);
			translation = realloc (translation, translation_size);
		}
		sprintf (&(translation [len]), "else\n{\n");
	}	

	//Translate every instruction contained in jump block
	for (i = 0; i < to_translate->num_instructions; i ++)
		translate_insn (to_translate->instructions [i], to_translate->instructions [i+1]);

	if (to_translate->flags & IS_BREAK)
	{
		len = strlen (translation);
		if (len + 7 > translation_size)
		{
			translation_size  = 2*(len + 7);
			translation = realloc (translation, translation_size);
		}
		sprintf (&(translation [len]), "break;\n");
	}
	else if (to_translate->flags & IS_CONTINUE)
	{
		len = strlen (translation);
		if (len + 10 > translation_size)
		{
			translation_size  = 2*(len + 10);
			translation = realloc (translation, translation_size);
		}
		sprintf (&(translation [len]), "continue;\n");
	}
	else if (to_translate->flags & IS_GOTO)
	{
		len = strlen (translation);
		if (len + 18 > translation_size)
		{
			translation_size  = 2*(len + 18);
			translation = realloc (translation, translation_size);
		}
		sprintf (&(translation [len]), "goto %p;\n\n", target);
	}

	for (i = 0; i < parent->num_jump_addrs; i ++)
	{
		if (to_translate->next->start == parent->jump_addrs [i] && !(parent->orig_addrs [i]))
		{
			len = strlen (translation);
			if (len + 12 > translation_size)
			{
				translation_size  = 2*(len + 12);
				translation = realloc (translation, translation_size);
			}
			sprintf (&(translation [len]), "%p:\n", to_translate->next->start);
		}
	}
}

//Jump block "preprocessing"
//Some per jump block routines require other routines to have been performed on EVERY jump block before they can be called.
//So we put first iteration routines in this function
void jump_block_preprocessing (jump_block* to_process, function* parent)
{
	int i = 0;
	int j = 0;
	unsigned int target = 0;
	unsigned int target2 = 0;
	if (to_process->instructions [to_process->num_instructions-1].type == insn_jmp)
	{
		target = to_process->instructions [to_process->num_instructions-1].size + index_to_addr (to_process->instructions [to_process->num_instructions-1].addr);
		target = relative_insn (&(to_process->instructions [to_process->num_instructions-1]), target);
	}
	if (to_process->instructions [to_process->num_instructions-1].type == insn_jcc)
	{
		target2 = to_process->instructions [to_process->num_instructions-1].size + index_to_addr (to_process->instructions [to_process->num_instructions-1].addr);
		target2 = relative_insn (&(to_process->instructions [to_process->num_instructions-1]), target2);
	}
	unsigned int orig = index_to_addr (to_process->instructions [to_process->num_instructions-1].addr);

	if (target2)
		to_process->next->flags |= IS_IF;

	if (to_process->flags & IS_LOOP)
		to_process->next->flags |= IS_AFTER_LOOP;

	if (target || to_process->instructions [to_process->num_instructions-1].type == insn_jcc)
	{
		for (i = 0; i < parent->num_jump_addrs; i++)
		{
			if (parent->jump_addrs [i] == target && parent->orig_addrs [i] != orig) //This instruction has the same target address as another, therefore we have a duplicate jump target
			{
				for (j = 0; j < parent->num_dups; j ++)
				{
					if (parent->dup_targets [j] == target)
						break;
				}
				if (j == parent->num_dups)
				{
					parent->num_dups ++;

					//Memory management for "}" placement algorithms
					if (parent->num_dups * sizeof (unsigned int) >= parent->dup_targets_buf_size)
					{
						parent->dup_targets_buf_size *= 2;
						parent->dup_targets = realloc (parent->dup_targets, parent->dup_targets_buf_size);
						parent->else_starts = realloc (parent->else_starts, parent->dup_targets_buf_size);
						parent->pivots = realloc (parent->pivots, parent->dup_targets_buf_size);
					}

					//Document memory addresses that are the targets of multiple jump instructions
					parent->dup_targets [parent->num_dups-1] = target;
					parent->else_starts [parent->num_dups-1] = 0;
					parent->pivots [parent->num_dups-1] = 0;
				}
			}
		}
	}

	if (target2 && target2 > orig)
	{
		struct search_params params;
		jump_block* if_target;
		params.key = target2;
		params.ret = (void**)&if_target;
		list_loop (search_start_addrs, to_process, to_process, params);

		if_target->flags |= IS_IF_TARGET;
	}
	if (target) //Possibly a while loop (block ends in unconditional jump)
	{
		struct search_params params;
		jump_block* while_block;
		jump_block* new_block;
		x86_oplist_t* current1;
		x86_oplist_t* current2;		
		params.key = target;
		params.ret = (void**)&while_block;
		list_loop (search_start_addrs, to_process, to_process, params); //Search for the jump block targetted by this jump instructions
		unsigned int target3;
		target3 = while_block->instructions [while_block->num_instructions-1].size + index_to_addr (while_block->instructions [while_block->num_instructions-1].addr);
		target3 = relative_insn (&(while_block->instructions [while_block->num_instructions-1]), target3);

		if (while_block->flags & IS_AFTER_LOOP)
		{
			for (i = 0; i < parent->num_jump_addrs; i++)
			{
				if (parent->jump_addrs [i] == target && parent->orig_addrs [i] == orig)
					parent->jump_addrs [i] = 0;
			}
			to_process->flags |= IS_BREAK;
		}
		else if (while_block->flags & IS_LOOP && target3 <= orig)
		{
			for (i = 0; i < parent->num_jump_addrs; i++)
			{
				if (parent->jump_addrs [i] == target && parent->orig_addrs [i] == orig)
					parent->jump_addrs [i] = 0;
			}
			to_process->flags |= IS_CONTINUE;
		}
		else if (to_process->next->flags & IS_IF_TARGET && !(target && target < orig) && !(to_process->flags & IS_AFTER_ELSE))
		{
			to_process->next->flags |= IS_ELSE; //End of IF statement, and ELSE statement exists, so the next block should be the start of a ELSE statement

			//Keep track of else statements that come directly before addresses pointed to by multiple jump instructions (see "}" placement algorithm in translate_jump_block)
			for (i = 0; i < parent->num_dups; i++)
			{
				if (target == parent->dup_targets [i])
				{
					parent->else_starts [i] = to_process->next->start; 
					break;
				}
			}

			while_block->flags |= IS_AFTER_ELSE;
		}
		else if (while_block->flags & IS_LOOP) //If this series of jump instructions ends in a backwards conditional jump, then this unconditional jump is the beginning of a while loop
		{
			new_block = malloc (sizeof (jump_block));
			*new_block = *while_block;
			link (to_process, new_block);
			new_block->instructions = malloc ((new_block->num_instructions+1) * sizeof (x86_insn_t));
			for (i = 0; i < new_block->num_instructions; i++) //Copy all instructions from while_block
			{
				new_block->instructions [i] = while_block->instructions [i];
				if (while_block->instructions [i].operand_count)
				{
					new_block->instructions [i].operands = malloc (sizeof (x86_oplist_t));
					current1 = new_block->instructions [i].operands;
					current2 = while_block->instructions [i].operands;
					current1->op = current2->op;
					current2 = current2->next;
					while (current2)
					{
						current1->next = malloc (sizeof (x86_oplist_t));
						current1 = current1->next;
						current1->op = current2->op;
						current2 = current2->next;
					}
					current1->next = NULL;
				}
			}
					
			new_block->instructions [i-1].bytes [0] = new_block->instructions [i-1].bytes [0];
			new_block->instructions [i-1].operands->op.type = op_absolute;
			new_block->instructions [i-1].operands->op.data.dword = while_block->end;
			new_block->instructions [i-1].operands->next = NULL;
			parent->num_jump_addrs ++;
			parent->jump_addrs [parent->num_jump_addrs-1] = while_block->end;
			parent->orig_addrs [parent->num_jump_addrs-1] = index_to_addr (new_block->instructions [i-1].addr);
		}
		else
		{
			for (i = 0; i < parent->num_jump_addrs; i++)
			{
				if (parent->jump_addrs [i] == target && parent->orig_addrs [i] == orig)
					parent->orig_addrs [i] = 0;
			}
			to_process->flags |= IS_GOTO;
		}
	}
}

void translate_func (function* to_translate)
{
	var* current_var;
	var* current_global = global_list;
	char* name = NULL;

	while (current_global && current_global->next != global_list)
		current_global = current_global->next;

	//Reset variable finding state machine
	var_list = NULL;
	callee_param = NULL;
	caller_param = NULL;
	translation_size = 256;
	translation = malloc (translation_size);
	bzero (translation, translation_size);

	bzero (next_line, 128);

	//Translate all jump blocks in function
	list_loop (jump_block_preprocessing, to_translate->jump_block_list, to_translate->jump_block_list, to_translate);
	list_loop (translate_jump_block, to_translate->jump_block_list, to_translate->jump_block_list, to_translate);

	if (current_global)
		list_loop (print_declarations, current_global, global_list);
	else if (global_list)
		list_loop (print_declarations, global_list, global_list);
	printf ("\n");

	//Print function header
	//NOTE: EAX will always be returned, what EAX means is up to the caller.
	//Since EAX is returned, a 32 bit int will always be returned
	if (string_hash_table)
		name = string_hash_table [to_translate->start_addr - 0x8048000];
	if (name)
		printf ("int %s (", name);
	else
		printf ("int func_%p (", to_translate->start_addr);
	current_var = callee_param;
	if (!callee_param)
		printf ("void)\n{\n");
	else
	{
		//Print parameter list
		printf ("%s %s", current_var->c_type, current_var->name);
		current_var = current_var->next;
		while (current_var != callee_param && current_var)
		{
			printf (", ");
			printf ("%s %s", current_var->c_type, current_var->name);
			current_var = current_var->next;
		}
		printf (")\n{\n");
		
	}

	//Print all variable declarations
	if (var_list)
		list_loop (print_declarations, var_list, var_list);
	printf ("\n");

	//Print the string translation of the given instructions
	printf ("%s}\n\n", translation);

	//Cleanup
	if (var_list)
		clean_var_list (var_list);
	if (callee_param)
		clean_var_list (callee_param);
	free (translation);
	free (to_translate->dup_targets);
	free (to_translate->else_starts);
	free (to_translate->pivots);
}

void translate_function_list (function* function_list)
{
	global_list = NULL;
	list_loop (translate_func, function_list, function_list);
	if (global_list)
		clean_var_list (global_list);
}

void print_declarations (var* to_print)
{
	if (to_print->type != DEREF && to_print->type != CONST && strcmp (to_print->name, "ebp") && strcmp (to_print->name, "esp")) //Dont need to declare constants. ESP and EBP are NOT general purpose
	{
		if (to_print->type == REG)
			printf ("register ");
		printf ("%s %s", to_print->c_type, to_print->name);
		if (to_print->type != PARAM)
			printf (";\n");
	}
}
