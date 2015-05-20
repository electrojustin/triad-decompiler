#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/capstone.h>

#include "var.h"
#include "jump_block.h"
#include "datastructs.h"

int name_ind = 0;
char last_name [20] = {'a'-1, 0, 0, 0,
		       0, 0, 0, 0,
		       0, 0, 0, 0,
		       0, 0, 0, 0,
		       0, 0, 0, 0};
char c_types [4][10] = {"char\0", "short\0", "int\0", "long long\0"};

char* gen_var_name (void)
{
	int i = name_ind;
	int len;
	char* name_buf;
	
	last_name [i] ++;

	while (last_name [i] > 'z')
	{
		if (i == 0) //Out of names
		{
			name_ind ++; //Add one letter
			if (name_ind == 19) //We've used far too many names (26^18 names)
				exit (1);
			for (i=0; i <= name_ind; i++)
				last_name [i] = 'a';
			break;
		}

		last_name [i] = 'a';
		i --;
		last_name [i] ++;
	}

	len = strlen (last_name);

	if (len == 3 && last_name [0] == 'e') //Don't want to confuse with registers, which have the naming pattern exz, x and z being other letters
		last_name [0] ++;
	if (len == 2 && (last_name [1] == 'x' || last_name [1] == 'h' || last_name [1] == 'l')) //Avoid 16 and 8 bit register names also e.g. ax, cx
		last_name [1] ++;

	name_buf = malloc (len+1);
	strcpy (name_buf, last_name);
	name_buf [len] = 0; //Make sure we null terminate
	return name_buf;
}

var* init_var (var* to_init, cs_x86_op operand)
{
	to_init->name = NULL;
	if (operand.type == X86_OP_IMM) //constant expression
	{
		to_init->type = CONST;
		to_init->name = malloc (20); //2^64-1 is 20 digits long
		bzero (to_init->name, 20);
		to_init->loc.disp = operand.imm;
		sprintf (to_init->name, constant_format, to_init->loc.disp);
		to_init->c_type = NULL;
	}
	else if (operand.type == X86_OP_REG) //Not a variable of any kind, but an x86 register
	{
		to_init->name = malloc (MAX_REGNAME);
		strcpy (to_init->name, cs_reg_name (handle, operand.reg));
		to_init->type = REG;
	}
	else
	{
		if (operand.type == X86_OP_MEM && !operand.mem.base && !operand.mem.index) //Absolute address, i.e. global variable
		{
			to_init->type = GLOBAL;
			to_init->loc.addr = operand.mem.disp;
		}
		else
		{
			if (operand.mem.index || (operand.mem.base && operand.mem.base != X86_REG_EBP && operand.mem.base != X86_REG_RBP)) //We're dereferencing a general purpose register
			{
				to_init->name = malloc (MAX_REGNAME);
				if (operand.mem.index)
					strcpy (to_init->name, cs_reg_name (handle, operand.mem.index));
				else
					strcpy (to_init->name, cs_reg_name (handle, operand.mem.base));
				to_init->type = DEREF;
			}
			else if (operand.mem.disp < 0)
				to_init->type = LOCAL;
			else //Should be a parameter otherwise
				to_init->type = PARAM;
			to_init->loc.disp = operand.mem.disp;
		}
	}

	to_init->next = NULL;
	return to_init;
}

void search_vars (var* to_check, var* key) 
{
	if (to_check->type == key->type)
	{
		if (to_check->type == GLOBAL)
		{
			if (to_check->loc.addr == key->loc.addr)
				key->next = to_check;
		}
		else if (to_check->type == REG)
		{
			if (to_check->name [1] == key->name [1])
				key->next = to_check;
		}
		else if (to_check->type == DEREF)
		{
			if (to_check->name [1] == key->name [1] && to_check->loc.disp == key->loc.disp)
				key->next = to_check;
		}
		else //Parameter, local, or constant
		{
			if (to_check->loc.disp == key->loc.disp)
				key->next = to_check;
		}
	}
}

var* add_var (cs_x86_op operand)
{
	var* to_add = init_var (malloc (sizeof (var)), operand); //Generate what the variable would be if it were to be added

	//Check for duplicate variables
	if (var_list)
		list_loop (search_vars, var_list, var_list, to_add); //Search the variable lists
	if (callee_param)
		list_loop (search_vars, callee_param, callee_param, to_add); //Search the parameter list for variable
	if (global_list)
		list_loop (search_vars, global_list, global_list, to_add);
	
	if (!to_add->next) //Search function will return pointer to first instance of variable if found. Otherwise, it's not a dupe
	{
		if (to_add->type == REG)
		{
			if (architecture == ELFCLASS32)
				to_add->c_type = c_types [2]; //All registers are 1 word long
			else
				to_add->c_type = c_types [3];
			to_add->loc.addr = 0;
		}
		else if (to_add->type == DEREF)
		{
			switch (operand.size)
			{
				case 1:
					to_add->c_type = c_types [0];
					break;
				case 2:
					to_add->c_type = c_types [1];
					break;
				case 4:
					to_add->c_type = c_types [2];
					break;
				case 8:
					to_add->c_type = c_types [3];
					break;
			}
		}
		else if (to_add->type != CONST)
		{
			to_add->name = gen_var_name (); //Generate a random variable name for non-constants. Constants' names are just a string representation of the constant.
			switch (operand.size)
			{
				case 1:
					to_add->c_type = c_types [0];
					break;
				case 2:
					to_add->c_type = c_types [1];
					break;
				case 4:
					to_add->c_type = c_types [2];
					break;
				case 8:
					to_add->c_type = c_types [3];
					break;
			}
		}

		if (to_add->type == PARAM)
		{
			//Add parameter to the callee_param list instead of the variable list
			//Parameters appear on the stack in the same order as they appear in a function prototype
			//Therefore, we must sort the parameters by displacement to print a correct function prototype
			if (callee_param && callee_param->next)
			{
				var* current = callee_param;
				do
				{
					if (current->next->loc.disp > to_add->loc.disp && current->loc.disp < to_add->loc.disp)
						break;
					current = current->next;
				} while (current->next != callee_param);
				link (current, to_add);
			}
			else if (callee_param)
			{
				if (to_add->loc.disp < callee_param->loc.disp)
				{
					var* temp = callee_param;
					callee_param = to_add;
					link (callee_param, temp);
				}
				else
					link (callee_param, to_add);
			}
			else
				callee_param = to_add;
		}
		else if (to_add->type == GLOBAL)
			link (global_list, to_add);
		else
			link (var_list, to_add); //Add variable to the list
	
		return to_add; //Return newly created variable
	}
	else
	{
		//Variable is a dupe, cleanup and return the first instance found
		var* next = to_add->next;
		cleanup_var (to_add);
		free (to_add);
		return next; //Return the other occurence of the variable in the variable list
	}
}

void cleanup_var (var* to_cleanup)
{
	if (to_cleanup->name)
		free (to_cleanup->name);
}

void clean_var_list (var* to_cleanup)
{
	list_cleanup (to_cleanup, cleanup_var);
}
