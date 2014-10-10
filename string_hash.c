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


#include "string_hash.h"

char** string_hash_table = NULL;

void add_string_entry (unsigned int offset, char* string)
{
	if (!string_hash_table)
	{
		string_table_size = (sizeof (char*) * (offset+1))*4;
		string_hash_table = malloc (string_table_size);
		bzero (string_hash_table, string_table_size);
	}
	else
	{
		if (offset * sizeof (char*) > string_table_size)
		{
			unsigned long long old_size = string_table_size;
			string_table_size = ((offset+1) * sizeof (char*))*4;
			string_hash_table = realloc (string_hash_table, string_table_size);
			bzero (string_hash_table + old_size, string_table_size-old_size);
		}

		string_hash_table [offset] = string;
	}
}

char* get_entry (unsigned int offset)
{
	if (offset * sizeof (char*) > string_table_size)
		return NULL;
	else
		return string_hash_table [offset];
}
