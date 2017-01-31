#!/usr/bin/python
# Written by Peter Schmidt-Nielsen (snp@mit.edu) in 2017
# Licensed under CC0 (Public Domain)

import ptrace
import utils

if __name__ == "__main__":
	import argparse

	p = argparse.ArgumentParser(description="Patch up binaries at runtime.")
	p.add_argument("--old", help="Old binary, to produce migration.")
	p.add_argument("--new", help="New binary, to produce migration.")
	p.add_argument("--apply", help="Apply a given migration.")
	p.add_argument("--pid", help="PID of process to attach to.")
	args = p.parse_args()
	print args

