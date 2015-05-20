CFLAGS=-O2
mrproper: triad clean
debug: CFLAGS=-g
debug: triad
triad: main.o elf_parser.o jump_block.o function.o var.o lang_gen.o
	gcc $(CFLAGS) main.o elf_parser.o jump_block.o function.o var.o lang_gen.o -o triad -lcapstone

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
