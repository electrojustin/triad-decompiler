#include <stdio.h>
#include <elf.h>

#pragma once

union ElfN_Sym_ptr
{
	Elf32_Sym* arch1;
	Elf64_Sym* arch2;
} ElfN_Sym_ptr;

union ElfN_Rel_ptr
{
	Elf32_Rel* arch1;
	Elf64_Rela* arch2;
} ElfN_Rel_ptr;

char* file_buf; //Buffer into which the file is read. Must be free'd
size_t file_size; //Size of file in bytes
unsigned int text_offset; //Number of bytes from file beginning where .text starts
unsigned int end_of_text;
unsigned int text_addr; //Virtual memory address .text is loaded into
unsigned int entry_point; //Entry point of executable. NOTE: probably don't want to start disassembling here
unsigned int base_addr;
unsigned int executable_segment_size;
int num_sections;
int num_relocs;
union ElfN_Sym_ptr symbol_table;
union ElfN_Sym_ptr symbol_table_end;
union ElfN_Sym_ptr dynamic_symbol_table;
union ElfN_Rel_ptr relocation_table;
int num_dynamic_symbols;
char* string_table;
char* dynamic_string_table;
char* section_string_table;
unsigned int main_addr;
char architecture;

void parse_elf (char* file_name);
void init_file_buf (char* file_name);
void get_num_sections (void);
void get_entry_point (void);
void get_section_names (void);
void parse_sections (void);
void get_num_sections64 (void);
void get_entry_point64 (void);
void get_section_names64 (void);
void parse_sections64 (void);
void find_main (void);
void find_main64 (void);
void elf_parser_cleanup (void);
Elf32_Sym* find_sym (Elf32_Sym* sym_tab, Elf32_Sym* end, unsigned int addr);
Elf32_Sym* find_reloc_sym (unsigned int addr);
Elf64_Sym* find_sym64 (Elf64_Sym* sym_tab, Elf64_Sym* end, unsigned int addr);
Elf64_Sym* find_reloc_sym64 (unsigned int addr);
int addr_to_index (unsigned int addr);
unsigned int index_to_addr (int index);
void init_elf_parser (char* file_name);
void get_dyn_syms (void);
void get_dyn_syms64 (void);
void get_text (void);
void get_text64 (void);
