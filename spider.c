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

//This is the main function for the spider disassembler.
//The spider disassembler was a midway program written to test jump block and function parsing.
//It essentially starts disassembling one function and "spiders" to functions called within the root function.
//Occasionally, one might find a function or bit of code in jump_block.c or function.c that is never called.
//This is likely because those bits of code were necessary for the spider disassembler.

//The spider disassembler has the added advantage that it isn't as easily fooled by anti-disassembly techniques (such as jump into instruction) as objdump.
//As such, I've left most of the code in in case someone wants a fancier disassembler than objdump.
//Unfortunately, it is currently broken, as of the Alpha 0.1 build.

#include <stdlib.h>
#include <libdis.h>

#include "program.h"
#include "function.h"

int main (int argc, char** argv)
{
	function* test_func = malloc (sizeof (function));
	init_file_buf (argv [1]);
	get_text();
	x86_init (opt_none, NULL, NULL);
	get_entry_point ();
	init_function (test_func, strtoul (argv [2], NULL, 16), file_buf, 1);
	resolve_conditional_jumps (test_func->jump_block_list);
	resolve_calls (test_func);
	print_function_list (test_func);
	function_list_cleanup (test_func, 1); //Make sure those operands don't leak
	free (file_buf);
	x86_cleanup ();
}
