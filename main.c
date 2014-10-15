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
