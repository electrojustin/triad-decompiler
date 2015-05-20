#!/bin/bash

cd tests

triad arith_test64 > arith_test64_trial
triad control_flow_test64 > control_flow_test64_trial
triad ./test64 > test64_trial

if [ -n "$(diff arith_test64_trial arith_test64_expected)" ]; then
	echo "ERROR: Failed arithmetic test"
	exit -1
fi

if [ -n "$(diff control_flow_test64_trial control_flow_test64_expected)" ]; then
	echo "ERROR: Failed control flow test"
	exit -1
fi

if [ -n "$(diff test64_trial test64_expected)" ]; then
	echo "ERROR: Failed test"
	exit -1
fi

echo "Round 2 of tests passed"

cd ..
