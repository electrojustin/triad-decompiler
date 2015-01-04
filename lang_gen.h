#include "function.h"
#include "jump_block.h"
#include "var.h"

#pragma once

char* translation; //String representation of equivalen C code
size_t translation_size;
extern char test_conditions [14] [3];
char next_line [128];
int num_tabs;
char language_flag; //f for full decompilation, p for partial decompilation (don't try to interpret control structures), d for disassembly (no decompilation)

void translate_func (function* to_translate); //Translate and print the C equivalent of the current function
void decompile_jump_block (jump_block* to_translate, function* parent); //Translate all instructions in jump block
void jump_block_preprocessing (jump_block* to_process, function* parent);
void decompile_insn (x86_insn_t instruction, x86_insn_t next_instruction, jump_block* parent);
void disassemble_insn (x86_insn_t instruction);
void disassemble_jump_block (jump_block* to_translate);
void print_declarations (var* to_print, char should_tab); //Helper function. We frequently need to print a variable's type followed by its name
void translate_function_list (function* function_list); //Print all functions in given function list
