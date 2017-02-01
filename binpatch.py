#!/usr/bin/python
# Written by Peter Schmidt-Nielsen (snp@mit.edu) in 2017
# Licensed under CC0 (Public Domain)

import os, sys, time, base64, subprocess, atexit
import ptrace
import utils

def make_migration(old_path, new_path):
	old = utils.Objdump(old_path)
	new = utils.Objdump(new_path)

	output = []

	# Get new functions, but ignore them for now.	
	new_functions = new.function_symbols.difference(old.function_symbols)

	# Find all symbols that have changed in contents.
	for func in old.function_symbols & new.function_symbols:
		data_old = old.read_symbol(func)
		data_new = new.read_symbol(func)
		old_address = old.symbols[func]["address"]
		if data_old != data_new:
			print "Updated symbol:", func
			# We now compute if we can simply overwrite, or must link in new code.
			fargs = (old_address, base64.b64encode(data_new))
			if len(data_new) <= len(data_old):
				output.append("write %x %s" % fargs)
			else:
				output.append("allocjump %x %s" % fargs)

	# Produce a final newline in the output.
	output.append("")
	return "\n".join(output)

command_argument_count = {
	"write": 2,
	"allocjump": 2,
}

def apply_migration(migration, pid):
	commands = []
	# XXX: TODO: Properly comment this code.
	# (I know, I know, this is a pretty ironic and awful comment...)
	# If it is after May 2017, and you email me at snp@mit.edu
	# and I haven't fixed this yet, and you're the first to email me
	# I'll paypal you $10.
	load_block = []
	load_length_so_far = 0

	print "=== Parsing migration"
	for line in migration.split("\n"):
		line = line.split("#")[0].strip()
		if not line:
			continue
		args = line.split(" ")
		assert args[0] in command_argument_count, "Bad migration command: %r" % (args[0],)
		assert len(args) == command_argument_count[args[0]] + 1, "Bad argument count to: %r" % (args[0],)

		if args[0] in ("write", "allocjump"):
			address, data = args[1:]
			address = int(address, 16)
			data = data.decode("base64")
			if args[0] == "write":
				print "Writing %i bytes to %x" % (len(data), address)
				commands.append(("write", address, data))
			else:
				print "Allocating %i bytes to %x" % (len(data), address)
				commands.append(("mmap_relative_jump", False, address, True, load_length_so_far))
				load_block.append(data)
				load_length_so_far += len(data)
		else:
			assert False, "BUG BUG BUG! Previous assert should make this dead code."

	# If we loaded any code, then add a command to load said code.
	if load_block:
		commands.insert(0, ("mmap", "".join(load_block)))

	print "Compiled %i commands." % len(commands)

	print
	print "=== Attaching to %i" % pid
	ctx = utils.Context(pid)
	ctx.attach()
	print "Attached."
	for command in commands:
		if command[0] == "write":
			print "Writing to %x" % address
			address, data = command[1:]
			ctx.mem[address] = data
		elif command[0] == "mmap":
			# Pick a convenient location to request the new code be loaded to.
			# Currently we load directly above the top of the current first mapping.
			# This is convenient because then gdb's asm layout will scroll directly into the loaded code.
			# TODO: Make this less fragile! This currently makes many assumptions, such as that the first
			# mapping is the main executable, and that there's space immediately above it to allocate to.
			# TODO: Check ctx.maps, and find a good robust place to put this block.
			data = command[1]
			data_size_rounded_up = ((len(data) + utils.PAGE_SIZE - 1) / utils.PAGE_SIZE) * utils.PAGE_SIZE
			print "Loading block of length %i" % data_size_rounded_up
			target_location = ctx.maps[0]["address"][1]
			ret = ctx.perform_syscall(utils.SYS_MMAP, [
				target_location,
				data_size_rounded_up,
				utils.PROT_READ | utils.PROT_EXEC,
				utils.MAP_PRIVATE | utils.MAP_ANONYMOUS,
				-1,
				0,
			])
			if ret > (2**64) - 4000:
				error_code = ret - 2**64
				print "Error on attachee's mmap syscall:", os.strerror(error_code)
				exit(3)
			mmap_address = ret
			print "Got mmaped block at: %x" % mmap_address
			ctx.mem[mmap_address] = data
		elif command[0] == "mmap_relative_jump":
			source_rel, source, dest_rel, dest = command[1:]
			if source_rel:
				source += mmap_address
			if dest_rel:
				dest += mmap_address
			print "Writing long jump from %x to %x" % (source, dest)
			ctx.write_long_jump(source, dest)
		else:
			assert False, "BUG BUG BUG! Invalid internal command."
	ctx.detach()
	print "Detached."

if __name__ == "__main__":
	import argparse

	p = argparse.ArgumentParser(description="Patch up binaries at runtime.")
	creation = p.add_argument_group(title="Migration Creation", description="These arguments are for producing migration files, for later application.")
	creation.add_argument("--old", help="Old binary, to produce migration.")
	creation.add_argument("--new", help="New binary, to produce migration.")
	creation.add_argument("-o", "--output", help="Output path to write a migration to.")

	apply_patch = p.add_argument_group(title="Apply", description="These arguments are for actually applying a migration to a given running binary.")
	apply_patch.add_argument("--apply", help="Apply a given migration.")
	apply_patch.add_argument("--pid", type=int, help="PID of process to attach to.")
	apply_patch.add_argument("--fork", help="Fork a given process, and use its PID. (For debugging purposes only.)")
	apply_patch.add_argument("--gdb", action="store_true", help="Attach gdb immediately after we're done detaching.")

	args = p.parse_args()

	# Ensure that only options from at most one exclusion set were used.
	exclusion_sets = [["old", "new", "output"], ["apply", "pid"]]
	count = sum(any(getattr(args, i) != None for i in exclusion_set) for exclusion_set in exclusion_sets)
	if count > 1:
		print >>sys.stderr, "Use only arguments for creating or applying migrations, not both."
		exit(1)

	if count == 0:
		print >>sys.stderr, "Do you want to create a migration, or apply one? (See --help)"
		exit(1)

	if args.output != None:
		data = make_migration(args.old, args.new)
		with open(args.output, "w") as f:
			f.write(data)

	if args.fork != None:
		print "Forking off as", args.fork
		pid = os.fork()
		if pid == 0:
			os.execl(args.fork, args.fork)
		def kill():
			print "Killing child."
			os.kill(pid, 9)
		atexit.register(kill)
		time.sleep(0.5)
		args.pid = pid

	if args.pid != None:
		with open(args.apply, "r") as f:
			migration_data = f.read()
		apply_migration(migration_data, args.pid)

	if args.gdb:
		print "Attaching gdb."
		subprocess.call(["gdb", "--pid=%i" % args.pid])

	if args.fork != None:
		time.sleep(3)

