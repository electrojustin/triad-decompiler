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
		if (current_name < file_buf || (unsigned long long)current_name > (unsigned long long)file_buf + file_size || current_offset < 0 || current_offset > file_size || (unsigned long long)current_offset > (unsigned long long)file_buf + file_size)
		{
			printf ("ERROR: Section number %d is malformed. Skipping...\n", loop);
			continue;
		}
		if (!strcmp (current_name, ".text")) //The part with the code
		{
			text_offset = section_table [loop].sh_offset;
			text_addr = section_table [loop].sh_addr;
			end_of_text = text_offset + section_table [loop].sh_size;
			if (text_offset < 0 || text_offset > file_size || end_of_text < 0 || end_of_text > file_size || (unsigned long long)text_offset > (unsigned long long)file_buf + file_size || text_offset > end_of_text)
			{
				printf ("CRITICAL ERROR: Malformed .text section\n");
				exit (1);
			}
		}
		if (!strcmp (current_name, ".symtab")) //Contains "symbols" for the program.
		{
			symbol_table = (Elf32_Sym*)(file_buf + current_offset);
			symbol_table_end = (Elf32_Sym*)((char*)symbol_table + section_table [loop].sh_size);
			if ((char*)symbol_table < file_buf || (unsigned long long)symbol_table > (unsigned long long)file_buf + file_size || (char*)symbol_table_end < file_buf || (unsigned long long)symbol_table_end > (unsigned long long)file_buf + file_size || symbol_table > symbol_table_end)
			{
				symbol_table = NULL;
				symbol_table_end = NULL;
				printf ("ERROR: Malformed symbol table.\n");
			}
		}
		if (!strcmp (current_name, ".dynsym")) //Contains symbols in external libraries to be used by the program
		{
			dynamic_symbol_table = (Elf32_Sym*)(file_buf + current_offset);
			if ((char*)dynamic_symbol_table < file_buf || (unsigned long long)dynamic_symbol_table > (unsigned long long)file_buf + file_size)
				printf ("ERROR: Malformed dynamic symbol table.\n");
		}
		if (!strcmp (current_name, ".rel.plt")) //Contains relocations, which reference dynamic symbols of functions in external libraries called by the program
		{
			relocation_table = (Elf32_Rel*)(file_buf + current_offset);
			num_relocs = section_table [loop].sh_size / section_table [loop].sh_entsize;
			if ((char*)relocation_table < file_buf || (unsigned long long)relocation_table > (unsigned long long)file_buf + file_size)
			{
				num_relocs = 0;
				relocation_table = NULL;
				printf ("ERROR: Malformed PLT.\n");
			}
		}
		if (!strcmp (current_name, ".dynstr")) //Strings for the dynamic symbols
		{
			dynamic_string_table = file_buf + current_offset;
			if (dynamic_string_table < file_buf || (unsigned long long)dynamic_string_table > (unsigned long long)file_buf + file_size)
			{
				dynamic_string_table = NULL;
				printf ("ERROR: Malformed dynamic string section.\n");
			}
		}
		if (!strcmp (current_name, ".strtab")) //Strings for the regular symbols
		{
			string_table = file_buf + current_offset;
			if (string_table < file_buf || (unsigned long long)string_table > (unsigned long long)file_buf + file_size)
			{
				string_table = NULL;
				printf ("ERROR: Malformed string table.\n");
			}
		}
				
	}
}

Elf32_Sym* find_sym (Elf32_Sym* sym_tab, Elf32_Sym* end, unsigned int addr)
{
	if (!sym_tab)
		return NULL;

	int loop = 0;

	while (sym_tab [loop].st_value != addr && &(sym_tab [loop]) < end)
		loop ++;
	
	if (sym_tab [loop].st_info == STT_NOTYPE)
		return NULL;
	else
		return &(sym_tab [loop]);
}

Elf32_Sym* find_reloc_sym (unsigned int addr)
{
	if (!relocation_table || !dynamic_symbol_table)
		return NULL;

	int loop = 0;

	while (relocation_table [loop].r_offset != addr && loop < num_relocs)
		loop ++;

	if (loop >= file_size)
		return NULL;
	else
		return &(dynamic_symbol_table [relocation_table [loop].r_info >> 8]);
}

void find_main (void)
{
	if (!symbol_table || !string_table)
		return;

	int loop = 0;

	loop ++;
	while (&(symbol_table [loop]) < symbol_table_end)
	{
		if (symbol_table [loop].st_name && symbol_table [loop].st_value)
		{
			if (!strcmp (string_table + symbol_table [loop].st_name, "main"))
			{
				main_addr = symbol_table [loop].st_value;
				return;
			}
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
	Elf32_Ehdr* header;

	init_file_buf (file_name);

	//Sanity check
	header = (Elf32_Ehdr*)file_buf;
	if (header->e_ident [0] != 0x7f || header->e_ident [1] != 'E' || header->e_ident [2] != 'L' || header->e_ident [3] != 'F')
	{
		elf_parser_cleanup ();
		printf ("CRITICAL ERROR: Not an ELF file.\n");
		exit (-1);
	}

	get_num_sections ();
	get_section_names ();
	parse_sections ();
	get_entry_point ();
	find_main ();
}

void elf_parser_cleanup (void)
{
	if (file_buf)
		free (file_buf);
}
