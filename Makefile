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
