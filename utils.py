#!/usr/bin/python
# Written by Peter Schmidt-Nielsen (snp@mit.edu) in 2017
# Licensed under CC0 (Public Domain)

import time, os, struct, subprocess, re
import ptrace

PAGE_SIZE = 4096

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
		ptrace.attach(self.pid)
		self.maps = ptrace.get_maps(self.pid)
		self.mem = ptrace.Memory(self.pid)

		# Scan all the executable pages for a syscall instruction.
		syscall = "\x0f\x05"
		for mapping in self.maps:
			if "x" not in mapping["flags"]:
				continue
			low, high = mapping["address"]
			data = self.mem[low:high]
			if syscall in data:
				self.syscall_addr = low + data.index(syscall)
				break
		else:
			print "No executable syscall instruction found!"
			exit(2)
		assert self.mem[self.syscall_addr:self.syscall_addr+2] == syscall

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

		self.test_write_capability(self.temporary_location)

	def detach(self):
		ptrace.detach(self.pid)

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

	def perform_syscall(self, call_number, args, signed=True):
		# First we get the initial register state.
		regs = ptrace.getregs(self.pid)
		original_regs = regs.copy()
		# Then we adjust the register state for a call.
		regs["rax"] = call_number
		linux_syscall_abi = ["rdi", "rsi", "rdx", "r10", "r8", "r9"]
		for arg, reg_name in zip(args, linux_syscall_abi):
			regs[reg_name] = arg
		regs["rip"] = self.syscall_addr
		ptrace.setregs(self.pid, regs)
		# We now single-step to execute the targetted syscall.
		ptrace.singlestep(self.pid)
		# We now read out the register state, to get return value and do sanity checking.
		return_regs = ptrace.getregs(self.pid)
		assert return_regs["rip"] == self.syscall_addr + 2, "Failed to execute just a single two-byte instruction! %r -> %r" % (self.syscall_addr, return_regs["rip"])
		result = return_regs["rax"]
		# Perform a sign fixup if requested.
		if signed and result & (1 << 63):
			result -= 2 ** 64
		# Finally, return the register state to how it was.
		ptrace.setregs(self.pid, original_regs)
		return result

	def write_long_jump(self, source_addr, dest_addr):
		distance = dest_addr - (source_addr + 5)
		data = "\xe9" + struct.pack("<i", distance)
		self.mem[source_addr:source_addr+5] = data

class SparseString:
	def __init__(self):
		self.data = {}

	def __contains__(self, x):
		if isinstance(x, slice):
			assert x.step is None, "Only two argument slices are supported."
			return all(i in self.data for i in xrange(x.start, x.stop))
		return x in self.data

	def __getitem__(self, x):
		if isinstance(x, slice):
			assert x.step is None, "Only two argument slices are supported."
			return "".join(self.data[i] for i in xrange(x.start, x.stop))
		return self[x:x+1]

	def __setitem__(self, x, y):
		if isinstance(x, slice):
			assert x.step is None, "Only two argument slices are supported."
			length = x.stop - x.start
			assert len(y) == length, "Length mismatch in write."
			self[x.start] = y
			return
		for i, c in enumerate(y):
			self.data[x + i] = c

class Objdump:
	def __init__(self, path):
		self.sections = {}
		self.symbols = {}
		self.symbol_cache = {}

		# Slurp the entire file.
		with open(path, "rb") as f:
			self.file_data = f.read()

		# Parse the section header.
		objdump_text = subprocess.check_output(["objdump", "-h", path])
		lines = objdump_text.split("\n")

		# Skip the first five line header, then parse in pairs.
		for line, flags in zip(lines[5:], lines[6:]):
			line = line.strip().split()
			flags = flags.strip().split()

			# Strip trailing commas.
			flags = [i[:-1] if i.endswith(",") else i for i in flags]

			# Skip non-loaded sections.
			if "LOAD" not in flags:
				continue

			idx, name, size, vma, lma, file_off, align = line
			idx = int(idx)
			size, vma, lma, file_off = map(lambda s: int(s, 16), (size, vma, lma, file_off))
			align = 2**int(align.split("**", 1)[1])

			assert name not in self.sections, "BUG BUG BUG! Duplicate section %r!" % (name,)

			assert vma == lma, "VMA != LMA currently not supported."

			self.sections[name] = {
				"idx": idx,
				"size": size,
				"vma": vma,
				"lma": lma,
				"file_off": file_off,
				"align": align,
				"flags": flags,
			}

		# Parse the symbols.
		objdump_text = subprocess.check_output(["objdump", "-t", path])
		lines = objdump_text.split("\n")
		while lines[-1] == "":
			lines.pop()

		# Skip the first four lines of header.
		for line in lines[4:]:
			assert line.count("\t") == 1, "Weirdly formatted objdump output."
			first_half, second_half = line.split("\t")
			address = int(first_half[:16], 16)
			flags = first_half[17:24]
			section = first_half[25:]
			size = int(second_half[:16], 16) 
#			assert second_half[16:30] == " "*14, "Weirdly formatted objdump output."
			name = second_half[16:].lstrip()

			assert flags[5] == "d" or (name not in self.symbols), "BUG BUG BUG! Duplicate non-debug symbol name %r!" % (name,)

			self.symbols[name] = {
				"address": address,
				"section": section,
				"size": size,
				"flags": flags,
			}

		# Compute our function symbols.
		self.function_symbols = set()
		for symbol, properties in self.symbols.iteritems():
			if properties["section"] in ("*UND*", "*ABS*"):
				continue
			if properties["size"] == 0:
				continue
			if properties["flags"][6] != "F":
				continue
			self.function_symbols.add(symbol)

		# Parse the relocation records.
		objdump_text = subprocess.check_output(["objdump", "-r", path])
		lines = objdump_text.split("\n")

		# Skip the first two lines of header.
		self.relocations = {}
		current_reloc_section = None
		for line in lines[2:]:
			if not line:
				continue
			m = re.match("RELOCATION RECORDS FOR [[](.*)[]]:", line)
			if m:
				current_reloc_section = m.groups()[0]
				continue
			if line.strip() == "OFFSET           TYPE              VALUE":
				continue
			offset, reloc_type, value = line.split()
			offset = int(offset, 16)
			delta = 0
			m = re.match("(.*)([-+]0x[0-9a-f]+)", value)
			if m:
				base, delta = m.groups()
				delta = int(delta, 16)

			if current_reloc_section not in self.relocations:
				self.relocations[current_reloc_section] = []
			self.relocations[current_reloc_section].append({
				"offset": offset,
				"type": reloc_type,
				"value": (base, delta),
			})

	def read_symbol(self, symbol):
		if symbol not in self.symbol_cache:
			properties = self.symbols[symbol]
			assert properties["section"] in self.sections, "Can't read_symbol() on symbol from invalid section."
			# Look up the address into the file by subtracting the symbol's address off of the section's LMA, then adding the file offset of the section.
			section = self.sections[properties["section"]]
			section_offset = properties["address"] - section["lma"]
			assert 0 <= section_offset < section["size"], "BUG BUG BUG! Symbol start is out of section!"
			assert section_offset + properties["size"] <= section["size"], "BUG BUG BUG! Symbol (implied) end is out of section!"
			file_offset = section_offset + section["file_off"]
			self.symbol_cache[symbol] = self.file_data[file_offset:file_offset+properties["size"]]
			assert len(self.symbol_cache[symbol]) == properties["size"], "BUG BUG BUG! Symbol ended up being the wrong size."
		return self.symbol_cache[symbol]

if __name__ == "__main__":
	import pprint, sys
	o = Objdump(sys.argv[1])
	print "=== Sections:"
	pprint.pprint(o.sections)
	print "=== Symbols:"
	pprint.pprint(o.symbols)
	print "=== Function symbols:", o.function_symbols
	print "=== Relocations:"
	pprint.pprint(o.relocations)

