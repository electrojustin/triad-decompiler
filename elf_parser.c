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

//Get information about .text section
void get_text (void)
{
	int loop = 0;
	unsigned int section_table_index;
	Elf32_Shdr* section_table;

	section_table_index = ((Elf32_Ehdr*)&(file_buf [0]))->e_shoff; //Use level hacking to get offset to section header table from elf header
	section_table = (Elf32_Shdr*)&(file_buf [section_table_index]); //Use level hacking to get section header

	loop ++;
	while (strcmp (section_string_table + section_table [loop].sh_name, ".text") && loop < num_sections)
		loop ++;

	if (loop >= num_sections)
	{
		printf ("CRITICAL ERROR: Executable data not found.\nProgram failed to find .text\n");
		exit (1);
	}
	text_offset = section_table [loop].sh_offset; //Get offset in bytes from beginning of file to .text
	text_addr = section_table [loop].sh_addr; //Get virtual memory address of .text
	end_of_text = section_table [loop].sh_offset; //This doesn't appear anywhere else in the elf parser, but it's useful for the elf editor
}

void get_syms (void)
{
	int loop = 0;
	unsigned int section_table_index;
	Elf32_Shdr* section_table;

	section_table_index = ((Elf32_Ehdr*)&(file_buf [0]))->e_shoff; //Use level hacking to get offset to section header table from elf header
	section_table = (Elf32_Shdr*)&(file_buf [section_table_index]); //Use level hacking to get section header

	loop ++;
	while (strcmp ((char*)(section_string_table + (unsigned long long)section_table [loop].sh_name), ".symtab") && loop < num_sections)
		loop ++;

	if (loop >= num_sections)
	{
		printf ("WARNING: Symbols not found.\nProgram failed to find symbol table.\nSymbol table was likely stripped entirely.\n");
		symbol_table = NULL;
		symbol_table_end = NULL;
	}
	else
	{
		symbol_table = (Elf32_Sym*)&(file_buf [section_table [loop].sh_offset]);
		symbol_table_end = (Elf32_Sym*)&(file_buf [section_table [loop+1].sh_offset]);
	}
}

void get_dynsyms (void)
{
	int loop = 0;
	unsigned int section_table_index;
	Elf32_Shdr* section_table;

	section_table_index = ((Elf32_Ehdr*)&(file_buf [0]))->e_shoff; //Use level hacking to get offset to section header table from elf header
	section_table = (Elf32_Shdr*)&(file_buf [section_table_index]); //Use level hacking to get section header

	loop ++;
	while (section_table [loop].sh_type != SHT_DYNSYM && loop < num_sections)
		loop ++;

	if (loop >= num_sections)
	{
		printf ("WARNING: Dynamic linking symbols not found.\nProgram failed to find dynamic symbol table.\nTarget likely does not use external libraries.\n");
		dynamic_symbol_table = NULL;
	}
	else
		dynamic_symbol_table = (Elf32_Sym*)&(file_buf [section_table [loop].sh_offset]);
}

void get_relocs (void)
{
	int loop = 0;
	unsigned int section_table_index;
	Elf32_Shdr* section_table;

	section_table_index = ((Elf32_Ehdr*)&(file_buf [0]))->e_shoff; //Use level hacking to get offset to section header table from elf header
	section_table = (Elf32_Shdr*)&(file_buf [section_table_index]); //Use level hacking to get section header

	loop ++;
	while (strcmp (section_string_table + section_table [loop].sh_name, ".rel.plt") && loop < num_sections)
		loop ++;

	if (loop >= num_sections)
	{
		printf ("WARNING: PLT relocation data not found.\nProgram failed to find .rel.plt\nTarget likely does not use external libraries\n");
		relocation_table = NULL;
	}
	else
		relocation_table = (Elf32_Rel*)&(file_buf [section_table [loop].sh_offset]);
}

void get_dynstrs (void)
{
	int loop = 0;
	unsigned int section_table_index;
	Elf32_Shdr* section_table;

	section_table_index = ((Elf32_Ehdr*)&(file_buf [0]))->e_shoff; //Use level hacking to get offset to section header table from elf header
	section_table = (Elf32_Shdr*)&(file_buf [section_table_index]); //Use level hacking to get section header

	loop ++;
	while (strcmp (section_string_table + section_table [loop].sh_name, ".dynstr") && loop < num_sections)
		loop ++;

	if (loop >= num_sections)
	{
		printf ("WARNING: Dynamic symbol string data not found.\nProgram failed to find .dynstr\nTarget likely does not use external libraries\n");
		dynamic_string_table = NULL;
	}
	else
		dynamic_string_table = &(file_buf [section_table [loop].sh_offset]);
}

//NOTE: this does not get the strings for section names. That is in .shstrtab. See: get_section_names ()
void get_strs (void)
{
	int loop = 0;
	unsigned int section_table_index;
	Elf32_Shdr* section_table;

	section_table_index = ((Elf32_Ehdr*)&(file_buf [0]))->e_shoff; //Use level hacking to get offset to section header table from elf header
	section_table = (Elf32_Shdr*)&(file_buf [section_table_index]); //Use level hacking to get section header

	loop ++;
	while (strcmp (section_string_table + section_table [loop].sh_name, ".strtab") && loop < num_sections)
		loop ++;

	if (loop >= num_sections)
	{
		printf ("WARNING: Symbol string data not found.\nProgram failed to find .strtab\nTarget likely had all symbols stripped\n");
		string_table = NULL;
	}
	else
		string_table = &(file_buf [section_table [loop].sh_offset]);
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

	while (relocation_table [loop].r_offset != addr && loop*sizeof (Elf32_Rel) + (unsigned long long)relocation_table - (unsigned long long)file_buf < file_size)
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
			add_string_entry (symbol_table [loop].st_value - 0x8048000, (char*)(string_table + (unsigned long long)symbol_table [loop].st_name));
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
	get_text ();
	get_syms ();
	get_dynsyms ();
	get_relocs ();
	get_dynstrs ();
	get_strs ();
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
