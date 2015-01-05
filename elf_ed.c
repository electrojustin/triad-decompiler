#include <stdlib.h>
#include "elf_ed.h"

void fix_header (unsigned int insertion_addr, int size)
{
	Elf32_Ehdr* header = (Elf32_Ehdr*)&(file_buf [0]);

	if (index_to_addr (header->e_phoff) > insertion_addr)
		header->e_phoff += size;

	if (index_to_addr (header->e_shoff) > insertion_addr)
		header->e_shoff += size;

	if (index_to_addr (header->e_shstrndx) > insertion_addr)
		header->e_shstrndx += size;

	if (header->e_entry > insertion_addr)
		header->e_entry += size;
}

void fix_program_table (unsigned int insertion_addr, int size)
{
	int loop = 0;
	unsigned int program_table_index;
	Elf32_Phdr* program_table;
	int num_program_entries;

	program_table_index = ((Elf32_Ehdr*)&(file_buf [0]))->e_phoff;
	num_program_entries = ((Elf32_Ehdr*)&(file_buf [0]))->e_phnum;
	program_table = (Elf32_Phdr*)&(file_buf [program_table_index]);

	for (loop; loop < num_program_entries; loop ++)
	{
		if (program_table [loop].p_offset > addr_to_index (insertion_addr))
			program_table [loop].p_offset += size;

		if (program_table [loop].p_vaddr > insertion_addr)
			program_table [loop].p_vaddr += size;

		if (program_table [loop].p_offset < addr_to_index (insertion_addr) && index_to_addr (program_table [loop].p_offset) + program_table [loop].p_memsz > insertion_addr)
		{
			program_table [loop].p_memsz += size;
			program_table [loop].p_filesz += size;
		}
	}
}

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
	unsigned int current;
	unsigned int target_addr;
	int insn_size;
	x86_insn_t instruction;
	int loop = 0;
	unsigned int section_table_index;
	Elf32_Shdr* section_table;

	section_table_index = ((Elf32_Ehdr*)&(file_buf [0]))->e_shoff; //Use level hacking to get offset to section header table from elf header
	section_table = (Elf32_Shdr*)&(file_buf [section_table_index]); //Use level hacking to get section header

	loop ++;
	while (strcmp (section_string_table + section_table [loop].sh_name, ".plt") && loop < num_sections)
		loop ++;

	if (loop >= num_sections)
		current = text_addr;
	else
		current = index_to_addr (section_table [loop].sh_offset);
	
	while (addr_to_index (current) < end_of_text)
	{
		insn_size = x86_disasm (file_buf, file_size, 0, addr_to_index (current), &instruction);
		current += insn_size;
		if (instruction.type == insn_jcc || instruction.type == insn_jmp || instruction.type == insn_call)
		{
			if (instruction.operands->op.type != op_relative_far && instruction.operands->op.type != op_relative_near)
			{
				//The absolute jumps and calls need fixing too, actually. Mostly in the PLT
				if (instruction.operands->op.type == op_expression)
				{
					if (*(unsigned int*)&(file_buf [addr_to_index (current - insn_size) + 2]) > insertion_addr && current < insertion_addr)
						*(unsigned int*)&(file_buf [addr_to_index (current - insn_size) + 2]) += size; //At least I don't have to think about endianness?
					if (*(unsigned int*)&(file_buf [addr_to_index (current - insn_size) + 2]) < insertion_addr && current > insertion_addr)
						*(unsigned int*)&(file_buf [addr_to_index (current - insn_size) + 2]) -= size; //At least I don't have to think about endianness?
				}
				if (instruction.operands->op.type == op_absolute)
				{
					if (*(unsigned int*)&(file_buf [addr_to_index (current - insn_size) + 1]) > insertion_addr && current < insertion_addr)
						*(unsigned int*)&(file_buf [addr_to_index (current - insn_size) + 1]) += size; //At least I don't have to think about endianness?
					if (*(unsigned int*)&(file_buf [addr_to_index (current - insn_size) + 1]) < insertion_addr && current > insertion_addr)
						*(unsigned int*)&(file_buf [addr_to_index (current - insn_size) + 1]) -= size; //At least I don't have to think about endianness?
				}
			}
			else
			{
				target_addr = relative_insn (&instruction, current);
				if (target_addr > insertion_addr && current < insertion_addr)
					*(signed int*)&(file_buf [addr_to_index (current - insn_size) + 1]) += size; //At least I don't have to think about endianness?
				if (target_addr < insertion_addr && current > insertion_addr)
					*(signed int*)&(file_buf [addr_to_index (current - insn_size) + 1]) -= size; //At least I don't have to think about endianness?
			}
		}
	}
}

char* insert_target (unsigned int insertion_addr, int size, char* insertion_buf)
{
	char* new_file_buf;
	int loop = 0;
	int loop2 = 0;

	fix_program_table (insertion_addr, size);
	fix_section_table (insertion_addr, size);
	fix_sym_tab (insertion_addr, size);
	fix_relative_addrs (insertion_addr, size);
	fix_header (insertion_addr, size);

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

	fix_program_table (start_addr, -1*size);
	fix_section_table (start_addr, -1*size);
	fix_sym_tab (start_addr, -1*size);
	fix_relative_addrs (start_addr, -1*size);
	fix_header (start_addr, -1*size);

	new_file_buf = malloc (file_size - size);

	for (loop; loop < addr_to_index (start_addr); loop ++)
		new_file_buf [loop] = file_buf [loop];

	loop += size;
	for (loop2 = addr_to_index (start_addr); loop2 < file_size - size; loop2 ++)
	{
		new_file_buf [loop2] = file_buf [loop];
		loop ++;
	}

	return new_file_buf;
}
