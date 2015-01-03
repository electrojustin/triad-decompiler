#include <libdis.h>
#include "elf_parser.h"

void fix_header (unsigned int insertion_addr, int size);
void fix_program_table (unsigned int insertion_addr, int size);
void fix_section_table (unsigned int insertion_addr, int size);
void fix_sym_tab (unsigned int insertion_addr, int size);
void fix_relative_addrs (unsigned int insertion_addr, int size);
char* insert_target (unsigned int insertion_addr, int size, char* insertion_buf);
char* del_target (unsigned int start_addr, int size);
