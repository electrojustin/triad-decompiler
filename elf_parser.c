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

#include "elf_parser.h"

//Load file into memory
void init_file_buf (char* file_name)
{
	FILE* executable;
	executable = fopen (file_name, "r");
	if (executable <= 0) //Something has gone wrong with opening the file
	{
		printf ("CRITICAL ERROR: File not found or bad permissions.\n");
		exit (1);
	}
	fseek (executable, 0, SEEK_END);
	file_size = ftell (executable);
	file_buf = malloc (file_size);
	fseek (executable, 0, SEEK_SET);
	fread (file_buf, 1, file_size, executable);
	fclose (executable);
}

//Use level hacking to get entry point from elf header
void get_entry_point (void)
{
	entry_point = ((Elf32_Ehdr*)&(file_buf [0]))->e_entry;
}

//Gets the names of the sections from .shstrtab
void get_section_names (void)
{
	Elf32_Shdr* section_table;

	section_table = (Elf32_Shdr*)&(file_buf [((Elf32_Ehdr*)&(file_buf [0]))->e_shoff]);
	section_string_table = file_buf + section_table [((Elf32_Ehdr*)file_buf)->e_shstrndx].sh_offset;
}

void get_num_sections (void)
{
	num_sections = ((Elf32_Ehdr*)&(file_buf [0]))->e_shnum;
}

//Finds information about a number of sections of interest by looping through the section table and looking for specific names
void parse_sections (void)
{
	int loop = 0;
	unsigned int section_table_index;
	Elf32_Shdr* section_table;
	char* current_name;
	unsigned int current_offset;

	text_offset = 0;
	text_addr = 0;
	end_of_text = 0;
	symbol_table = 0;
	symbol_table_end = 0;
	dynamic_symbol_table = 0;
	relocation_table = 0;
	dynamic_string_table = 0;
	string_table = 0;

	section_table_index = ((Elf32_Ehdr*)&(file_buf [0]))->e_shoff;
	section_table = (Elf32_Shdr*)&(file_buf [section_table_index]);	

	for (loop; loop < num_sections; loop ++)
	{
		current_name = section_string_table + section_table [loop].sh_name;
		current_offset = section_table [loop].sh_offset;
		if (!strcmp (current_name, ".text")) //The part with the code
		{
			text_offset = section_table [loop].sh_offset;
			text_addr = section_table [loop].sh_addr;
			end_of_text = text_offset + section_table [loop].sh_size;
		}
		if (!strcmp (current_name, ".symtab")) //Contains "symbols" for the program.
		{
			symbol_table = (Elf32_Sym*)(file_buf + current_offset);
			symbol_table_end = (Elf32_Sym*)((char*)symbol_table + section_table [loop].sh_size);
		}
		if (!strcmp (current_name, ".dynsym")) //Contains symbols in external libraries to be used by the program
			dynamic_symbol_table = (Elf32_Sym*)(file_buf + current_offset);
		if (!strcmp (current_name, ".rel.plt")) //Contains relocations, which reference dynamic symbols of functions in external libraries called by the program
		{
			relocation_table = (Elf32_Rel*)(file_buf + current_offset);
			num_relocs = section_table [loop].sh_size / section_table [loop].sh_entsize;
		}
		if (!strcmp (current_name, ".dynstr")) //Strings for the dynamic symbols
			dynamic_string_table = file_buf + current_offset;
		if (!strcmp (current_name, ".strtab")) //Strings for the regular symbols
			string_table = file_buf + current_offset;
	}
}

Elf32_Sym* find_sym (Elf32_Sym* sym_tab, unsigned int addr)
{
	if (!sym_tab)
		return NULL;

	int loop = 0;

	while (sym_tab [loop].st_value != addr && sym_tab [loop].st_info != STT_NOTYPE)
		loop ++;
	
	if (sym_tab [loop].st_info == STT_NOTYPE)
		return NULL;
	else
		return &(sym_tab [loop]);
}

Elf32_Sym* find_reloc_sym (unsigned int addr)
{
	int loop = 0;

	while (relocation_table [loop].r_offset != addr && loop < num_relocs)
		loop ++;

	if (loop >= file_size)
		return NULL;
	else
		return &(dynamic_symbol_table [relocation_table [loop].r_info >> 8]);
}

void load_string_hashes (void)
{
	if (!symbol_table || !string_table)
		return;

	int loop = 0;

	loop ++;
	while (&(symbol_table [loop]) < symbol_table_end)
	{
		if (symbol_table [loop].st_name && symbol_table [loop].st_value)
		{
			add_string_entry (symbol_table [loop].st_value - 0x8048000, string_table + symbol_table [loop].st_name);
			if (!strcmp (string_table + symbol_table [loop].st_name, "main"))
				main_addr = symbol_table [loop].st_value;
		}
		loop ++;
	}
}

//Handy function for changing a virtual memory address to index for file_buf
int addr_to_index (unsigned int addr)
{
	return addr-text_addr+text_offset;
}

//Handy function for changing an index for file_buf to a virtual memory address
unsigned int index_to_addr (int index)
{
	return index-text_offset+text_addr;
}

void parse_elf (char* file_name)
{
	init_file_buf (file_name);
	get_num_sections ();
	get_section_names ();
	parse_sections ();
	get_entry_point ();
	load_string_hashes ();
}

void elf_parser_cleanup (void)
{
	if (string_hash_table)
		free (string_hash_table);
	if (file_buf)
		free (file_buf);
}
