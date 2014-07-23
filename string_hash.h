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

//The title of this file is a bit misleading.
//This section of the program does not actually employ a proper hashing function - it just happens to work like an associative array.
//The key is not a hashing of the relevant string, but rather its relative location in virtual memory.

//A quick background on this file:
//I was originally going to seperate functions by cutting one off when a particular memory address had an associated string.
//Since this associated string check would need to be performed once per instruction, I figured it had to be efficient.
//This associative array was originally meant as a high performance means of getting strings symbol-and it still is.
//But if the symbols were stripped from a file, this method would end badly.
//I decided it would just be easier to cut off a function at the "push %ebp" at the beginning of an adjacent function.
//There are areas in lang_gen.c that need function names though, so I left it.
//TL;DR this should probably be replaced by some O(n) algorithm in program.c that doesn't use an incredible amount of memory, since we don't need fast anymore.

#include <stdlib.h>
#include <strings.h>

#pragma once

extern char** string_hash_table;
unsigned long long string_table_size;

void add_string_entry (unsigned int offset, char* string);
char* get_entry (unsigned int offset);
