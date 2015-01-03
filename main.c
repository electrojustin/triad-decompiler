#include <stdlib.h>
#include <libdis.h>

#include "elf_parser.h"
#include "lang_gen.h"

int main (int argc, char** argv)
{
	if (argc > 3 || argc <= 1)
	{
		printf ("Triad decompiler version 0.1 Alpha Test.\nCopyright 2014 Justin Green.\nUsage: triad <file name> <(optional)start address>\n");
		exit (1);
	}
	else
	{
		unsigned int beginning_address;
		function* func;
		parse_elf (argv [1]);
		x86_init (opt_none, NULL, NULL);
		if (argc == 3)
		{
			beginning_address = strtoul (argv [2], NULL, 16);
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
			exit (1);
		}
		func->next = NULL;
		resolve_calls (func);
		translate_function_list (func);
		function_list_cleanup (func, 1); //Make sure those operands don't leak
		elf_parser_cleanup ();
		x86_cleanup ();
	}
}
