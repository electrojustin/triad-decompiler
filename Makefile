mrproper: triad clean
debug:
	make -C src debug
triad: 
	make -C src triad
sys_tests:
	make -C tests sys_tests && tests/do_tests.sh
sys_tests64:
	make -C tests sys_tests64 && tests/do_tests64.sh
clean:
	make -C src clean
clean_tests:
	make -C tests clean
install:
	install src/triad /usr/bin/triad
