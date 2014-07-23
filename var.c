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

#include "var.h"
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

var* init_var (var* to_init, x86_op_t operand)
{
	to_init->name = NULL;
	if (operand.type == op_immediate) //constant expression
	{
		to_init->type = CONST;
		to_init->name = malloc (20); //2^64-1 is 20 digits long
		bzero (to_init->name, 20);
		to_init->loc.disp = operand.data.dword;
		sprintf (to_init->name, "%d", to_init->loc.disp);
		to_init->c_type = NULL;
	}
	else if (operand.type == op_register) //Not a variable of any kind, but an x86 register
	{
		to_init->name = malloc (MAX_REGNAME);
		strcpy (to_init->name, operand.data.reg.name);
		to_init->type = REG;
	}
	else
	{
		if (operand.type == op_offset) //Absolute address, i.e. global variable
		{
			to_init->type = GLOBAL;
			to_init->loc.addr = operand.data.dword;
		}
		else //Should be op_expression unless we're being fed jump instructions or intermediates
		{
			if (!(operand.data.expression.base.type & reg_fp) && !(operand.data.expression.base.type & reg_sp) && operand.data.expression.base.name [0]) //We're dereferencing a general purpose register
			{
				to_init->name = malloc (MAX_REGNAME);
				strcpy (to_init->name, operand.data.expression.base.name);
				to_init->type = DEREF;
			}
			else if (!operand.data.expression.base.name [0])
			{
				to_init->type = GLOBAL;
				to_init->loc.addr = operand.data.dword;
			}
			else if (operand.data.expression.disp < 0)
				to_init->type = LOCAL;
			else //Should be a parameter otherwise
				to_init->type = PARAM;
			to_init->loc.disp = operand.data.expression.disp;
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

var* add_var (x86_op_t operand)
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
			to_add->c_type = c_types [2]; //All registers are 1 word long
			to_add->loc.addr = 0;
		}
		else if (to_add->type == DEREF)
			to_add->c_type = c_types [operand.datatype-1];
		else if (to_add->type != CONST)
		{
			to_add->name = gen_var_name (); //Generate a random variable name for non-constants. Constants' names are just a string representation of the constant.
			to_add->c_type = c_types [operand.datatype-1]; //op_byte through op_dword happen to be numbers 1-5.
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
