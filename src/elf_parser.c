#include <stdlib.h>
#include <string.h>

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

void get_entry_point64 (void)
{
	entry_point = ((Elf64_Ehdr*)&(file_buf [0]))->e_entry;
}

//Gets the names of the sections from .shstrtab
void get_section_names (void)
{
	Elf32_Shdr* section_table;

	section_table = (Elf32_Shdr*)&(file_buf [((Elf32_Ehdr*)&(file_buf [0]))->e_shoff]);
	section_string_table = file_buf + section_table [((Elf32_Ehdr*)file_buf)->e_shstrndx].sh_offset;
}

void get_section_names64 (void)
{
	Elf64_Shdr* section_table;

	section_table = (Elf64_Shdr*)&(file_buf [((Elf64_Ehdr*)&(file_buf [0]))->e_shoff]);
	section_string_table = file_buf + section_table [((Elf64_Ehdr*)file_buf)->e_shstrndx].sh_offset;
}

void get_num_sections (void)
{
	num_sections = ((Elf32_Ehdr*)&(file_buf [0]))->e_shnum;
}

void get_num_sections64 (void)
{
	num_sections = ((Elf64_Ehdr*)&(file_buf [0]))->e_shnum;
}

//Finds information about a number of sections of interest by looping through the section table and looking for specific names
void parse_sections (void)
{
	int loop = 0;
	unsigned int section_table_index;
	Elf32_Shdr* section_table;
	char* current_name;
	unsigned int current_offset;

	symbol_table.arch1 = 0;
	symbol_table_end.arch1 = 0;
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
		if (!strcmp (current_name, ".symtab")) //Contains "symbols" for the program.
		{
			symbol_table.arch1 = (Elf32_Sym*)(file_buf + current_offset);
			symbol_table_end.arch1 = (Elf32_Sym*)((char*)symbol_table.arch1 + section_table [loop].sh_size);
			if ((char*)symbol_table.arch1 < file_buf || (unsigned long long)symbol_table.arch1 > (unsigned long long)file_buf + file_size || (char*)symbol_table_end.arch1 < file_buf || (unsigned long long)symbol_table_end.arch1 > (unsigned long long)file_buf + file_size || symbol_table.arch1 > symbol_table_end.arch1)
			{
				symbol_table.arch1 = NULL;
				symbol_table_end.arch1 = NULL;
				printf ("ERROR: Malformed symbol table.\n");
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

void parse_sections64 (void)
{
	int loop = 0;
	unsigned int section_table_index;
	Elf64_Shdr* section_table;
	char* current_name;
	unsigned int current_offset;

	symbol_table.arch2 = 0;
	symbol_table_end.arch2 = 0;
	string_table = 0;

	section_table_index = ((Elf64_Ehdr*)&(file_buf [0]))->e_shoff;
	section_table = (Elf64_Shdr*)&(file_buf [section_table_index]);	

	for (loop; loop < num_sections; loop ++)
	{
		current_name = section_string_table + section_table [loop].sh_name;
		current_offset = section_table [loop].sh_offset;
		if (current_name < file_buf || (unsigned long long)current_name > (unsigned long long)file_buf + file_size || current_offset < 0 || current_offset > file_size || (unsigned long long)current_offset > (unsigned long long)file_buf + file_size)
		{
			printf ("ERROR: Section number %d is malformed. Skipping...\n", loop);
			continue;
		}
		if (!strcmp (current_name, ".symtab")) //Contains "symbols" for the program.
		{
			symbol_table.arch2 = (Elf64_Sym*)(file_buf + current_offset);
			symbol_table_end.arch2 = (Elf64_Sym*)((char*)symbol_table.arch2 + section_table [loop].sh_size);
			if ((char*)symbol_table.arch2 < file_buf || (unsigned long long)symbol_table.arch2 > (unsigned long long)file_buf + file_size || (char*)symbol_table_end.arch2 < file_buf || (unsigned long long)symbol_table_end.arch2 > (unsigned long long)file_buf + file_size || symbol_table.arch2 > symbol_table_end.arch2)
			{
				symbol_table.arch2 = NULL;
				symbol_table_end.arch2 = NULL;
				printf ("ERROR: Malformed symbol table.\n");
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

Elf64_Sym* find_sym64 (Elf64_Sym* sym_tab, Elf64_Sym* end, unsigned int addr)
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
	if (!relocation_table.arch1 || !dynamic_symbol_table.arch1)
		return NULL;

	int loop = 0;

	while (relocation_table.arch1 [loop].r_offset != addr && loop < num_dynamic_symbols)
		loop ++;

	if (loop >= num_dynamic_symbols)
		return NULL;
	else
		return &(dynamic_symbol_table.arch1 [relocation_table.arch1 [loop].r_info >> 8]);
}

Elf64_Sym* find_reloc_sym64 (unsigned int addr)
{
	if (!relocation_table.arch2 || !dynamic_symbol_table.arch2)
		return NULL;

	int loop = 0;

	while (relocation_table.arch2 [loop].r_offset != addr && loop < num_dynamic_symbols)
		loop ++;

	if (loop >= num_dynamic_symbols)
		return NULL;
	else
		return &(dynamic_symbol_table.arch2 [relocation_table.arch2 [loop].r_info >> 32]);
}

void get_dyn_syms (void)
{
	Elf32_Ehdr* header = (Elf32_Ehdr*)file_buf;
	Elf32_Phdr* segment_table = (Elf32_Phdr*)(file_buf + header->e_phoff);
	Elf32_Dyn* dynamic_table;
	int i = 0;
	int j = 0;

	dynamic_string_table = NULL;
	dynamic_symbol_table.arch1 = NULL;
	relocation_table.arch1 = NULL;
	num_dynamic_symbols = 0;

	for (i; i < header->e_phnum; i ++)
	{
		if (segment_table [i].p_type == PT_DYNAMIC)
			break;
	}

	if (i >= header->e_phnum)
	{
		printf ("Error: No dynamic linking information\n");
		return;
	}

	dynamic_table = (Elf32_Dyn*)(file_buf + segment_table [i].p_offset);

	j = 0;
	while (dynamic_table [j].d_tag != DT_NULL)
	{
		if (dynamic_table [j].d_tag == DT_STRTAB)
			dynamic_string_table = (char*)(file_buf + addr_to_index (dynamic_table [j].d_un.d_ptr));
		if (dynamic_table [j].d_tag == DT_SYMTAB)
			dynamic_symbol_table.arch1 = (Elf32_Sym*)(file_buf + addr_to_index (dynamic_table [j].d_un.d_ptr));
		if (dynamic_table [j].d_tag == DT_RELSZ)
			num_dynamic_symbols += dynamic_table [j].d_un.d_val /sizeof (Elf32_Rel);
		if (dynamic_table [j].d_tag == DT_PLTRELSZ)
			num_dynamic_symbols = dynamic_table [j].d_un.d_val / sizeof (Elf32_Rel);
		if (dynamic_table [j].d_tag == DT_REL)
			relocation_table.arch1 = (Elf32_Rel*)(file_buf + addr_to_index (dynamic_table [j].d_un.d_ptr));
	
		j ++;
	}
}

void get_dyn_syms64 (void)
{
	Elf64_Ehdr* header = (Elf64_Ehdr*)file_buf;
	Elf64_Phdr* segment_table = (Elf64_Phdr*)(file_buf + header->e_phoff);
	Elf64_Dyn* dynamic_table;
	int i = 0;
	int j = 0;

	dynamic_string_table = NULL;
	dynamic_symbol_table.arch2 = NULL;
	relocation_table.arch2 = NULL;
	num_dynamic_symbols = 0;

	for (i; i < header->e_phnum; i ++)
	{
		if (segment_table [i].p_type == PT_DYNAMIC)
			break;
	}

	if (i >= header->e_phnum)
	{
		printf ("Error: No dynamic linking information\n");
		return;
	}

	dynamic_table = (Elf64_Dyn*)(file_buf + segment_table [i].p_offset);
	
	j = 0;
	while (dynamic_table [j].d_tag != DT_NULL)
	{
		if (dynamic_table [j].d_tag == DT_STRTAB)
			dynamic_string_table = (char*)(file_buf + addr_to_index (dynamic_table [j].d_un.d_ptr));
		if (dynamic_table [j].d_tag == DT_SYMTAB)
			dynamic_symbol_table.arch2 = (Elf64_Sym*)(file_buf + addr_to_index (dynamic_table [j].d_un.d_ptr));
		if (dynamic_table [j].d_tag == DT_RELASZ)
			num_dynamic_symbols += dynamic_table [j].d_un.d_ptr /sizeof (Elf64_Rela);
		if (dynamic_table [j].d_tag == DT_PLTRELSZ)
			num_dynamic_symbols = dynamic_table [j].d_un.d_ptr / sizeof (Elf64_Rela);
		if (dynamic_table [j].d_tag == DT_RELA)
			relocation_table.arch2 = (Elf64_Rela*)(file_buf + addr_to_index (dynamic_table [j].d_un.d_ptr));
	
		j ++;
	}
}

void find_main (void)
{
	if (!symbol_table.arch1 || !string_table)
		return;

	int loop = 0;

	loop ++;
	while (&(symbol_table.arch1 [loop]) < symbol_table_end.arch1)
	{
		if (symbol_table.arch1 [loop].st_name && symbol_table.arch1 [loop].st_value)
		{
			if (!strcmp (string_table + symbol_table.arch1 [loop].st_name, "main"))
			{
				main_addr = symbol_table.arch1 [loop].st_value;
				return;
			}
		}
		loop ++;
	}
}

void find_main64 (void)
{
	if (!symbol_table.arch2 || !string_table)
		return;

	int loop = 0;

	loop ++;
	while (&(symbol_table.arch2 [loop]) < symbol_table_end.arch2)
	{
		if (symbol_table.arch2 [loop].st_name && symbol_table.arch2 [loop].st_value)
		{
			if (!strcmp (string_table + symbol_table.arch2 [loop].st_name, "main"))
			{
				main_addr = symbol_table.arch2 [loop].st_value;
				return;
			}
		}
		loop ++;
	}
}

//Handy function for changing a virtual memory address to index for file_buf
int addr_to_index (unsigned int addr)
{
	return addr-base_addr;
}

//Handy function for changing an index for file_buf to a virtual memory address
unsigned int index_to_addr (int index)
{
	return index+base_addr;
}

void get_text (void)
{
	text_addr = entry_point;
	text_offset = addr_to_index (text_addr);
	Elf32_Phdr* segment_table = (Elf32_Phdr*)(file_buf + ((Elf32_Ehdr*)file_buf)->e_phoff);
	int i;

	for (i = 0; i < ((Elf32_Ehdr*)file_buf)->e_phnum; i ++)
	{
		if (segment_table [i].p_vaddr <= text_addr && segment_table [i].p_vaddr + segment_table [i].p_memsz > text_addr)
		{
			end_of_text = segment_table [i].p_vaddr + segment_table [i].p_memsz;
			break;
		}
	}

	if (i >= ((Elf32_Ehdr*)file_buf)->e_phnum)
	{
		printf ("ERROR: entry point not in loadable segment\n");
		exit (-1);
	}
}

void get_text64 (void)
{
	text_addr = entry_point;
	text_offset = addr_to_index (text_addr);
	Elf64_Phdr* segment_table = (Elf64_Phdr*)(file_buf + ((Elf64_Ehdr*)file_buf)->e_phoff);
	int i;

	for (i = 0; i < ((Elf64_Ehdr*)file_buf)->e_phnum; i ++)
	{
		if (segment_table [i].p_vaddr <= text_addr && segment_table [i].p_vaddr + segment_table [i].p_memsz > text_addr)
		{
			end_of_text = segment_table [i].p_vaddr + segment_table [i].p_memsz;
			break;
		}
	}

	if (i >= ((Elf64_Ehdr*)file_buf)->e_phnum)
	{
		printf ("ERROR: entry point not in loadable segment\n");
		exit (-1);
	}
}


//Initialize some globals that have to deal with the ELF we're reading
//Note: this must be called whether or not you're actually using the parser
void init_elf_parser (char* file_name)
{
	init_file_buf (file_name);

	Elf32_Ehdr* header = (Elf32_Ehdr*)file_buf;
	Elf64_Ehdr* header64 = (Elf64_Ehdr*)file_buf;

	//Sanity check
	header = (Elf32_Ehdr*)file_buf;
	if (header->e_ident [EI_MAG0] != 0x7f || header->e_ident [EI_MAG1] != 'E' || header->e_ident [EI_MAG2] != 'L' || header->e_ident [EI_MAG3] != 'F')
	{
		elf_parser_cleanup ();
		printf ("CRITICAL ERROR: Not an ELF file.\n");
		exit (-1);
	}
	if (header->e_shoff > file_size)
	{
		elf_parser_cleanup ();
		printf ("ERROR: ELF file is corrupt. Invalid section header offset. Sections have probably been stripped, please specify a starting address.\n");
		exit (-1);
	}
	if (header->e_phoff > file_size)
	{
		elf_parser_cleanup ();
		printf ("CRITICAL ERROR: ELF file is corrupt Invalid program header offset.\n");
		exit (-1);
	}

	architecture = header->e_ident [EI_CLASS];

	if (architecture == ELFCLASSNONE)
	{
		printf ("CRITICAL ERROR: Invalid architecture");
		exit (-1);
	}
	else if (architecture == ELFCLASS32)
	{
		Elf32_Phdr* program_headers = (Elf32_Phdr*)(file_buf + header->e_phoff);
		int i;

		for (i = 0; i < header->e_phnum; i ++)
		{
			if (program_headers [i].p_type == PT_LOAD)
			{
				base_addr = program_headers [i].p_vaddr;
				executable_segment_size = program_headers [i].p_filesz;
				break;
			}
		}
		if (i == header->e_phnum)
		{
			printf ("CRITICAL ERROR: No loadable segments\n");
			exit (-1);
		}

		symbol_table.arch1 = NULL;
		symbol_table_end.arch1 = NULL;
		num_relocs = 0;
		string_table = NULL;

		get_dyn_syms ();
		get_entry_point ();
		get_text ();
	}
	else if (architecture == ELFCLASS64)
	{
		Elf64_Phdr* program_headers = (Elf64_Phdr*)(file_buf + header64->e_phoff);
		int i;

		for (i = 0; i < header64->e_phnum; i ++)
		{
			if (program_headers [i].p_type == PT_LOAD)
			{
				base_addr = program_headers [i].p_vaddr;
				executable_segment_size = program_headers [i].p_filesz;
				break;
			}
		}
		if (i == header64->e_phnum)
		{
			printf ("CRITICAL ERROR: No loadable segments\n");
			exit (-1);
		}

		symbol_table.arch2 = NULL;
		symbol_table_end.arch2 = NULL;
		num_relocs = 0;
		string_table = NULL;

		get_dyn_syms64 ();
		get_entry_point64 ();
		get_text64 ();
	}
	else
	{
		printf ("CRITICAL ERROR: Invalid ELF class %d", architecture);
		exit (-1);
	}
}

void parse_elf (char* file_name)
{
	init_elf_parser (file_name);

	if (architecture == ELFCLASS32)
	{
		get_num_sections ();
		get_section_names ();
		parse_sections ();
		find_main ();
	}
	else
	{
		get_num_sections64 ();
		get_section_names64 ();
		parse_sections64 ();
		find_main64 ();
	}
}

void elf_parser_cleanup (void)
{
	if (file_buf)
		free (file_buf);
}
