sys_tests: test arith_test control_flow_test

sys_tests64: test64 arith_test64 control_flow_test64

test: test.c
	gcc -m32 test.c -o test
arith_test: arith_test.c
	gcc -m32 arith_test.c -o arith_test
control_flow_test: control_flow_test.c
	gcc -m32 control_flow_test.c -o control_flow_test
test64: test.c
	gcc test.c -o test64
arith_test64: arith_test.c
	gcc arith_test.c -o arith_test64
control_flow_test64: control_flow_test.c
	gcc control_flow_test.c -o control_flow_test64

clean:
	rm test test64 arith_test arith_test64 control_flow_test control_flow_test64 *trial
