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


#include <stdio.h>
#include <elf.h>

#pragma once

char* file_buf; //Buffer into which the file is read. Must be free'd
unsigned int file_size; //Size of file in bytes
unsigned int text_offset; //Number of bytes from file beginning where .text starts
unsigned int end_of_text;
unsigned int text_addr; //Virtual memory address .text is loaded into
unsigned int entry_point; //Entry point of executable. NOTE: probably don't want to start disassembling here
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
