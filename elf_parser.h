#include <stdio.h>
#include <elf.h>

#pragma once

char* file_buf; //Buffer into which the file is read. Must be free'd
unsigned int file_size; //Size of file in bytes
unsigned int text_offset; //Number of bytes from file beginning where .text starts
unsigned int end_of_text;
unsigned int text_addr; //Virtual memory address .text is loaded into
unsigned int entry_point; //Entry point of executable. NOTE: probably don't want to start disassembling here
unsigned int base_addr;
unsigned int executable_segment_size;
int num_sections;
int num_relocs;
Elf32_Sym* symbol_table;
Elf32_Sym* symbol_table_end;
Elf32_Sym* dynamic_symbol_table;
Elf32_Rel* relocation_table;
char* string_table;
char* dynamic_string_table;
char* section_string_table;
unsigned int main_addr;

void parse_elf (char* file_name);
void init_file_buf (char* file_name);
void get_num_sections (void);
void get_entry_point (void);
void get_section_names (void);
void parse_sections (void);
void find_main (void);
void elf_parser_cleanup (void);
Elf32_Sym* find_sym (Elf32_Sym* sym_tab, Elf32_Sym* end, unsigned int addr);
Elf32_Sym* find_reloc_sym (unsigned int addr);
int addr_to_index (unsigned int addr);
unsigned int index_to_addr (int index);
void init_elf_parser (char* file_name);
