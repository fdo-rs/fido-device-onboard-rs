#!/bin/bash
set -euox pipefail

function run_tests() {
	if [ "$TEST_CASE" = "fdo-bootc" ]; then
		./fdo-bootc.sh
	else
		echo "Error: Test case $TEST_CASE not found!"
		exit 1
	fi
}

run_tests
exit 0
