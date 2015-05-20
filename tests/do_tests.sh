#!/bin/bash

cd tests

triad arith_test > arith_test_trial
triad control_flow_test > control_flow_test_trial
triad ./test > test_trial

if [ -n "$(diff arith_test_trial arith_test_expected)" ]; then
	echo "ERROR: Failed arithmetic test"
	exit -1
fi

if [ -n "$(diff control_flow_test_trial control_flow_test_expected)" ]; then
	echo "ERROR: Failed control flow test"
	exit -1
fi

if [ -n "$(diff test_trial test_expected)" ]; then
	echo "ERROR: Failed test"
	exit -1
fi

echo "Round 1 of tests passed"

cd ..
