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

#include "elf_ed.h"

void fix_section_table (unsigned int insertion_addr, int size)
{
	int loop = 0;
	unsigned int section_table_index;
	Elf32_Shdr* section_table;

	section_table_index = ((Elf32_Ehdr*)&(file_buf [0]))->e_shoff; //Use level hacking to get offset to section header table from elf header
	section_table = (Elf32_Shdr*)&(file_buf [section_table_index]); //Use level hacking to get section header

	for (loop; loop < num_sections; loop ++)
	{
		if (index_to_addr (section_table [loop].sh_offset) > insertion_addr)
			section_table [loop].sh_offset += size;
	}
}

void fix_sym_tab (unsigned int insertion_addr, int size)
{
	int loop = 0;

	while (&(symbol_table [loop]) < symbol_table_end)
	{
		if (symbol_table [loop].st_value > insertion_addr)
			symbol_table [loop].st_value += size;
		loop ++;
	}
}

void fix_relative_addrs (unsigned int insertion_addr, int size)
{
	unsigned int current = text_addr;
	unsigned int target_addr;
	int insn_size;
	x86_insn_t instruction;
	
	while (addr_to_index (current) < end_of_text)
	{
		insn_size = x86_disasm (file_buf, file_size, 0, addr_to_index (current), &instruction);
		current += insn_size;
		if (instruction.type == insn_jcc || instruction.type == insn_jmp || instruction.type == insn.call)
		{
			if (instruction.operands->op.type != op_relative_far && instruction.operands->op.type != op_relative_near)
				continue;

			target_addr = relative_insn (&instruction, current);
			if (target_addr > insertion_addr && current < insertion_addr)
				*(signed int*)&(file_buf [addr_to_index (current - insn_size) + 1]) += size; //At least I don't have to think about endianness?
			if (target_addr < insertion_addr && current > insertion_addr)
				*(signed int*)&(file_buf [addr_to_index (current - insn_size) + 1]) -= size; //At least I don't have to think about endianness?
		}
	}
}

char* insert_target (unsigned int insertion_addr, int size, char* insertion_buf)
{
	char* new_file_buf;
	int loop = 0;
	int loop2 = 0;

	fix_section_table (insertion_addr, size);
	fix_sym_tab (insertion_addr, size);
	fix_relative_addrs (insertion_addr, size);

	new_file_buf = malloc (file_size + size);

	for (loop; loop < addr_to_index (insertion_addr); loop ++)
		new_file_buf [loop] = file_buf [loop];

	for (loop = addr_to_index (insertion_addr); loop < addr_to_index (insertion_addr) + size; loop ++)
	{
		new_file_buf [loop] = insertion_buf [loop2];
		loop2 ++;
	}

	loop2 = addr_to_index (insertion_addr);
	for (loop = addr_to_index (insertion_addr) + size; loop < file_size + size; loop ++)
	{
		new_file_buf [loop] = file_buf [loop2];
		loop2 ++;
	}

	return new_file_buf;
}

char* del_target (unsigned int start_addr, int size)
{
	char* new_file_buf;
	int loop = 0;
	int loop2 = 0;

	fix_section_table (start_addr, -1*size);
	fix_sym_tab (start_addr, -1*size);
	fix_relative_addrs (start_addr, -1*size);

	new_file_buf = malloc (file_size - size);

	for (loop; loop < addr_to_index (start_addr); loop ++)
		new_file_buf [loop] = file_buf [loop];

	loop += size;
	for (loop2; loop2 < file_size - size; loop2 ++)
	{
		new_file_buf [loop] = file_buf [loop2];
		loop ++;
	}

	return new_file_buf;
}

void main (int argc, char** argv)
{
	FILE* output;
	char* output_buf;
	unsigned int start_addr;

	if (argc < 4 || argc > 5)
	{
		printf ("Triad elf editor version 0.1 Alpha Test.\nCopyright 2014 Justin Green.\nUsage: elf_ed <target file> <input file> <starting address\n or, elf_ed -d <target_file> <starting_address> <number of bytes to delete>\n");
		exit (1);
	}

	else if (argc == 4)
	{
		FILE* input;
		char* input_buf;
		size_t input_file_size;

		parse_elf (argv [1]);

		input = fopen (argv [2], "r");
		if (input <= 0)
		{
			printf ("CRITICAL ERROR: File not found or bad permissions.\n");
			exit (1);
		}
		start_addr = strtoul (argv [3], NULL, 16);
		if (start_addr == 0)
		{
			printf ("CRITICAL ERROR: Invalid starting address.\n");
			exit (1);
		}

		seek (input, 0, SEEK_END);
		input_file_size = ftell (input);
		input_buf = malloc (input_file_size);
		fseek (input, 0, SEEK_SET);
		fread (input_buf, 1, input_file_size, input);
		fclose (input);

		output_buf = insert_target (start_addr, input_file_size, input_buf);
		output = fopen (argv [1], "w+");
		fseek (output, 0, SEEK_SET);
		fwrite (output_buf, 1, file_size + input_file_size, output);

		fclose (output);
		free (input_buf);
		free (output_buf);
	}
	else if (!strcmp (argv [1], "-d"))
	{
		int size_of_deletion;

		parse_elf (argv [2]);

		start_addr = strtoul (argv [3], NULL, 16);
		if (start_addr == 0)
		{
			printf ("CRITICAL ERROR: Invalid starting address.\n");
			exit (1);
		}
		size_of_deletion = atoi (argv [4], NULL, 16);

		output_buf = del_target (start_addr, size_of_deletion);
		output = fopen (argv [2], "w+");
		fseek (output, 0, SEEK_SET);
		fwrite (output_buf, 1, file_size + input_file_size, output);

		fclose (output);
		free (output_buf);
	}
	else
		printf ("Invalid option %s\n", argv [1]);
}
