#Copyright (C) 2014 Justin Green
#SHA512 sum of resume: ee1dcaa00b931696d73f0d978e39ac2c8302de27a5034b7035bd9111d1f48ddf9fae46842baa3af2a56f17f8043cdd5760ced014c223a13fab1ad29cbfb3748c
#How to use this checksum: open up directory with my resume and type "sha512sum resume.docx" into the bash prompt.
#Then compare the two checksums.
#
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in
#all copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#THE SOFTWARE.*/

CFLAGS=-O2
mrproper: triad clean
debug: CFLAGS=-g
debug: triad elf_ed
triad: main.o elf_parser.o jump_block.o function.o var.o lang_gen.o
	gcc $(CFLAGS) main.o elf_parser.o jump_block.o function.o var.o lang_gen.o -o triad -ldisasm
sys_tests: test arith_test control_flow_test
test: test.c
	gcc -g -m32 test.c -o test
arith_test: arith_test.c
	gcc -g -m32 arith_test.c -o arith_test
control_flow_test: control_flow_test.c
	gcc -g -m32 control_flow_test.c -o control_flow_test
elf_ed: elf_ed_main.o elf_ed.o elf_parser.o jump_block.o
	gcc $(CFLAGS) elf_ed_main.o elf_ed.o elf_parser.o jump_block.o -o elf_ed -ldisasm
elf_ed.o: elf_ed.c elf_ed.h elf_parser.h
	gcc $(CFLAGS) -c elf_ed.c
elf_ed_main.o: elf_ed_main.c elf_ed.h elf_parser.h
	gcc $(CFLAGS) -c elf_ed_main.c
main.o: main.c elf_parser.h function.h
	gcc $(CFLAGS) -c main.c
elf_parser.o: elf_parser.h elf_parser.c
	gcc $(CFLAGS) -c elf_parser.c
jump_block.o: jump_block.c jump_block.h datastructs.h elf_parser.h
	gcc $(CFLAGS) -c jump_block.c
function.o: function.c function.h datastructs.h jump_block.h
	gcc $(CFLAGS) -c function.c
var.o: var.c var.h datastructs.h
	gcc $(CFLAGS) -c var.c
lang_gen.o: lang_gen.c lang_gen.h var.h function.h jump_block.h
	gcc $(CFLAGS) -c lang_gen.c
clean:
	rm main.o var.o lang_gen.o jump_block.o elf_parser.o function.o
install:
	install ./triad /usr/bin/triad
