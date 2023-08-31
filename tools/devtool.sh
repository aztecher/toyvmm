#!/bin/bash

arg=$1

err_msg="devtool.sh requires an argument, but no to be supplied. skip..."
priv_tests_toyvmm_module=""
priv_tests_vmm_module="test_tap_set_offload"

# Supported commands.
CMD_TEST_ALL="test-all"
CMD_TEST_NO_PRIV="test-no-priv"
CMD_TEST_PRIV="test-priv"

# General functions

function usage() {
	echo "devtool.sh is the helper tools for developing toyvmm."
	echo ""
	echo "Usage:"
	echo "  devtool.sh <COMMAND>"
	echo ""
	echo "Commands:"
	echo "  $CMD_TEST_NO_PRIV : Only tests that do not require privileged."
	echo "  $CMD_TEST_PRIV    : Only tests that need to be privileged are executed."
	echo "  $CMD_TEST_ALL     : Execute all tests (test-no-priv + test-priv)."
	echo ""
}


# Command related variables and functions

priv_tests_toyvmm_module=""
priv_tests_vmm_module="test_priv"

function test_no_priv() {
	if [ -z $priv_tests_toyvmm_module ]; then
		cargo test -p toyvmm
	else
		cargo test -p toyvmm -- --skip $priv_tests_toyvmm_module
	fi
	if [ -z $priv_tests_vmm_module ]; then
		cargo test -p vmm
	else
		cargo test -p vmm -- --skip $priv_tests_vmm_module
	fi
}

function test_priv() {
	if [ -z $priv_tests_toyvmm_module ]; then
		echo "The test that needs to be privileged is not in the toyvmm module."
	else
		sudo -E cargo test -p toyvmm $priv_tests_toyvmm_module
	fi
	if [ -z $priv_tests_vmm_module ]; then
		echo "The test that needs to be privileged is not in the vmm module."
	else
		sudo -E cargo test -p vmm $priv_tests_vmm_module
	fi
}

function test_all() {
	test_no_priv
	test_priv
}


if [ $arg == $CMD_TEST_NO_PRIV ]; then
	test_no_priv
elif [ $arg == $CMD_TEST_PRIV ]; then
	test_priv
elif [ $arg == $CMD_TEST_ALL ]; then
	test_all
else
	echo $err_msg
	echo ""
	usage
	exit 1
fi
