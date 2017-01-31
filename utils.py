#!/usr/bin/python
# Written by Peter Schmidt-Nielsen (snp@mit.edu) in 2017
# Licensed under CC0 (Public Domain)

import time, os, struct
import ptrace

PROT_READ  = 0x1
PROT_WRITE = 0x2
PROT_EXEC  = 0x4
MAP_PRIVATE = 0x02
MAP_ANONYMOUS = 0x20
SYS_MMAP = 9

class Context:
	def __init__(self, pid):
		self.pid = pid

	def attach(self):
		ptrace.attach(pid)
		self.maps = ptrace.get_maps(pid)
		self.mem = ptrace.Memory(pid)

		# Scan all the executable pages for a syscall instruction.
		syscall = "\x0f\x05"
		for mapping in self.maps:
			if "x" not in mapping["flags"]:
				continue
			low, high = mapping["address"]
			data = self.mem[low:high]
			if syscall in data:
				syscall_addr = low + data.index(syscall)
				break
		else:
			print "No executable syscall instruction found!"
			exit(2)
		assert self.mem[syscall_addr:syscall_addr+2] == syscall

		# Scan for a read-write page to dump temporary strings.
		for mapping in self.maps:
			if "r" not in mapping["flags"] or "w" not in mapping["flags"]:
				continue
			low, high = mapping["address"]
			if high - low > 128:
				self.temporary_location = low
				break
		else:
			print "No read-write pages found! (Really!?)"
			exit(2)

		test_write_capability(self.temporary_location)

	def test_write_capability(self, addr):
		# Do a test of the read write capabilities.
		spot = slice(addr, addr+8, None)
		original = nonce = self.mem[spot]
		while nonce == original:
			nonce = os.urandom(8)
		# Test that we can change the value.
		self.mem[spot] = nonce
		assert self.mem[spot] == nonce
		# Change it back it its original value, and check that we succeeded.
		self.mem[spot] = original
		assert self.mem[spot] == original

	def perform_syscall(self, call_number, args):
		# First we get the initial register state.
		regs = ptrace.getregs(self.pid)
		original_regs = regs.copy()
		# Then we adjust the register state for a call.
		regs["rax"] = call_number
		linux_syscall_abi = ["rdi", "rsi", "rdx", "r10", "r8", "r9"]
		for arg, reg_name in zip(args, linux_syscall_abi):
			regs[reg_name] = arg
		regs["rip"] = syscall_addr
		ptrace.setregs(self.pid, regs)
		# We now single-step to execute the targetted syscall.
		ptrace.singlestep(self.pid)
		# We now read out the register state, to get return value and do sanity checking.
		return_regs = ptrace.getregs(self.pid)
		assert return_regs["rip"] == syscall_addr + 2, "Failed to execute just a single two-byte instruction! %r -> %r" % (syscall_addr, return_regs["rip"])
		result = return_regs["rax"]
		if result & (1 << 63):
			result -= 2 ** 64
		# Finally, return the register state to how it was.
		ptrace.setregs(self.pid, original_regs)
		return result

	def write_long_jump(self, source_addr, dest_addr):
		distance = dest_addr - (source_addr + 5)
		data = "\xe9" + struct.pack("<i", distance)
		self.mem[source_addr:source_addr+5] = data

# Code location.
code_location = maps[0]["address"][1] + 4096
print "Code location:", hex(code_location)

#r = perform_syscall(62, [23913, 9])
r = perform_syscall(9, [code_location, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0])
print "Got:", hex(r)

test_write_capability(r)
#print "Got:", r, os.strerror(-r)

ptrace.detach(pid)
#ptrace.cont(pid)
time.sleep(3.0)

