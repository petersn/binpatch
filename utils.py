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

# The size (in bytes) of the field that is written to to accomplish a given type of relocation.
relocation_byte_sizes = {
	"R_X86_64_32": 4,
	"R_X86_64_PC32": 4,
}

def color_diff(a, b, special_indices=set()):
	red = "\033[91m"
	blue = "\033[94m"
	normal = "\033[0m"
	o = []
	for i in xrange(len(a)):
		if i/2 in special_indices:
			o.append(blue + a[i] + normal)
		elif i < len(b) and b[i] != a[i]:
			o.append(red + a[i] + normal)
		else:
			o.append(a[i])
	return "".join(o)

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
				"relocations": [],
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
		self.relocations = []
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

			self.relocations.append({
				"section": current_reloc_section,
				"offset": offset,
				"type": reloc_type,
				"value": (base, delta),
			})

		# Compute a table of approximate matches for generous lookup.
		#self.generous_lookup = self.symbols.copy()
		self.hard_to_locate_symbols = set()
		for symbol_name, symbol in self.symbols.iteritems():
			if "@" in symbol_name:
				self.hard_to_locate_symbols.add(symbol_name.split("@", 1)[0])
#				self.generous_lookup[symbol_name.split("@", 1)[0]] = symbol

		# As final processing, we now match up relocations with symbols.
		for reloc in self.relocations:
			# TODO: Replace this linear time scan with a binary search.
			# We now try to find a symbol that is patched up by this relocation.
			for symbol in self.symbols.itervalues():
				if symbol["section"] != reloc["section"]:
					continue
				section = self.sections[symbol["section"]]
				# Make sure the reloc is within the given symbol in this section.
				# To do this we first compute the offset into the section at which the symbol resides.
				section_offset_start = symbol["address"] - section["lma"]
				section_offset_end   = symbol["address"] + symbol["size"] - section["lma"]
				# Note: I'm not careful about relocations that span the end or start of a symbol.
				# I should probably assert on those here...
				if not (section_offset_start <= reloc["offset"] < section_offset_end):
					continue
				symbol["relocations"].append(reloc)
				# Note: I assume that this reloc will only match one symbol, and break for efficiency.
				break

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

	def read_relocated_symbol(self, symbol_name, symbol_table, ignored_symbols):
		symbol = self.symbols[symbol_name]
		section = self.sections[symbol["section"]]
		data = list(self.read_symbol(symbol_name))
		ignore_indices = set()
		for reloc in symbol["relocations"]:
			# Because reloc["offset"] is the offset of the given relocation in the section,
			# we first add the section's LMA to get a global address. We then subtract
			# the symbol's address, which gives an offset into the list `data` from above.
			reloc_target_address = reloc["offset"] + section["lma"]
			data_offset = reloc_target_address - symbol["address"]
			reloc_byte_size = relocation_byte_sizes[reloc["type"]]
			assert 0 <= data_offset <= len(data) - reloc_byte_size, "Relocation isn't within bounds!"

			if reloc["value"][0] in ignored_symbols:
				print "IGNORING:", reloc["value"][0]
				ignore_indices |= set(xrange(data_offset, data_offset + reloc_byte_size))
				continue

			# We now compute the actual value to insert at the relocation point.
			reloc_value = symbol_table[reloc["value"][0]]["address"]
			print "Name:", reloc["value"]
			print "Value: %x" % reloc_value
			reloc_value += reloc["value"][1]
			print "Got:   %x" % reloc_value

			# Apply the actual relocation.
			if reloc["type"] == "R_X86_64_32":
				data[data_offset : data_offset + reloc_byte_size] = struct.pack("<i", reloc_value)
			elif reloc["type"] == "R_X86_64_PC32":
				data[data_offset : data_offset + reloc_byte_size] = struct.pack("<i", reloc_value - reloc_target_address)
			else:
				print "Unhandled relocation type:", reloc["type"]
		return "".join(data), ignore_indices

		# Firstly, we read the symbol.
#		properties = self.symbols[symbol]
#		data = list(self.read_symbol(symbol))
#		section = self.sections[properties["section"]]
#		section_offset_start = properties["address"] - section["lma"]
#		section_offset_end   = properties["address"] + properties["size"] - section["lma"]
#		print "Symbol range: %i-%i" % (section_offset_start, section_offset_end)
#		# We now proceed to apply all appropriate relocations to the read data.
#		for reloc in relocations:
#			if reloc["section"] != properties["section"]:
#				continue
#			if not (section_offset_start <= reloc["offset"] < section_offset_end):
#				continue
#			print "Found applicable reloc:", reloc

#if __name__ == "__main__":
#	o1 = Objdump("examples/counter")
#	o2 = Objdump("examples/counter.o")
#	o2.read_relocated_symbol("main", o2.relocations)
#	exit()

if __name__ == "__main__":
	import pprint, sys
	o = Objdump(sys.argv[1])
#	print "=== Sections:"
#	pprint.pprint(o.sections)
#	print "=== Symbols:"
#	pprint.pprint(o.symbols)
	print "=== Function symbols:", o.function_symbols
	print "=== Relocations:"
	pprint.pprint(o.symbols["main"])

	o2 = Objdump("examples/counter")
	ORIG = o2.read_symbol("main").encode("hex")

	print "=== Read relocated:"
	LATER, to_ignore = o.read_relocated_symbol("main", o2.symbols, o2.hard_to_locate_symbols)
	LATER = LATER.encode("hex")

	print ORIG
	print color_diff(LATER, ORIG, to_ignore)

