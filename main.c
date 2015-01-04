#include <stdlib.h>
#include <libdis.h>

#include "elf_parser.h"
#include "lang_gen.h"

int main (int argc, char** argv)
{
	int i;
	int j;
	char* file_name = NULL;
	char* beginning_address_string = NULL;
	language_flag = 'f';

	//Parse the command line
	for (i = 1; i < argc; i ++)
	{
		if (argv [i][0] == '-')
		{
			j = 1;
			while (argv [i][j] != '\0')
			{
				switch (argv [i][j])
				{
					case 'f':
						break;
					case 'p':
						language_flag = 'p';
						break;
					case 'd':
						language_flag = 'd';
						break;
					default:
						printf ("Unrecognized flag \"%c\"\n", argv [i][j]);
						exit (-1);
				}
				j ++;
			}
		}
		else if (file_name == NULL)
			file_name = argv [i];
		else if (beginning_address_string == NULL)
			beginning_address_string = argv [i];
		else
		{
			printf ("Unrecognized option \"%s\"\n", argv [i]);
			exit (-1);
		}
	}
					

	unsigned int beginning_address;
	function* func;
	if (beginning_address_string == NULL)
		parse_elf (file_name);
	x86_init (opt_none, NULL, NULL);
	if (beginning_address_string)
	{
		init_elf_parser ();
		init_file_buf (file_name);
		beginning_address = strtoul (beginning_address_string, NULL, 16);
		if (beginning_address)
			func = init_function (malloc (sizeof (function)), beginning_address);
		else
			printf ("Error: invalid start address\n");
	}
	else if (main_addr)
		func = init_function (malloc (sizeof (function)), main_addr);
	else
	{
		printf ("Error: could not find main and no start address specified\n");
		exit (-1);
	}
	func->next = NULL;
	resolve_calls (func);
	translate_function_list (func);
	function_list_cleanup (func, 1); //Make sure those operands don't leak
	elf_parser_cleanup ();
	x86_cleanup ();
}
