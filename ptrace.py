#!/usr/bin/python
# Written by Peter Schmidt-Nielsen (snp@mit.edu) in 2017
# Licensed under CC0 (Public Domain)

__all__ = ["Memory"]

def export_func(f):
	__all__.append(f.func_name)
	return f

import ctypes, os, subprocess
from ctypes import c_void_p, c_int, c_uint, c_long, c_ulong

# From /usr/include/sys/user.h
class user_regs_struct(ctypes.Structure):
	_fields_ = [
		("r15", c_ulong),
		("r14", c_ulong),
		("r13", c_ulong),
		("r12", c_ulong),
		("rbp", c_ulong),
		("rbx", c_ulong),
		("r11", c_ulong),
		("r10", c_ulong),
		("r9", c_ulong),
		("r8", c_ulong),
		("rax", c_ulong),
		("rcx", c_ulong),
		("rdx", c_ulong),
		("rsi", c_ulong),
		("rdi", c_ulong),
		("orig_rax", c_ulong),
		("rip", c_ulong),
		("cs", c_ulong),
		("eflags", c_ulong),
		("rsp", c_ulong),
		("ss", c_ulong),
		("fs_base", c_ulong),
		("gs_base", c_ulong),
		("ds", c_ulong),
		("es", c_ulong),
		("fs", c_ulong),
		("gs", c_ulong),
	]

	def to_dict(self):
		return {k: getattr(self, k) for k, ctypes_type in self._fields_}

	@classmethod
	def from_dict(cls, d):
		result = cls()
		for k, v in d.iteritems():
			setattr(result, k, v)
		return result

_libc = ctypes.CDLL("libc.so.6", use_errno=True)

# long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
ptrace = _libc.ptrace
ptrace.args = [c_uint, c_uint, c_void_p, c_void_p]
ptrace.restype = c_long

# pid_t waitpid(pid_t pid, int *status, int options);
waitpid = _libc.waitpid
waitpid.args = [c_uint, ctypes.POINTER(c_int), c_int]
waitpid.restype = c_uint

PTRACE_CONT = 7
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_SYSCALL = 24

def check(result):
	if result < 0:
		errno = ctypes.get_errno()
		raise OSError(errno, os.strerror(errno), "")

def _basic(command, pid):
	check(ptrace(command, pid, 0, 0))
	status = c_int()
	returned_pid = waitpid(pid, ctypes.byref(status), 0)
	check(returned_pid)
	assert returned_pid == pid, "We didn't pass WNOHANG, so waitpid should only be able to return the passed in PID!"
	return status

@export_func
def attach(pid):
	return _basic(PTRACE_ATTACH, pid)

@export_func
def detach(pid):
	check(ptrace(PTRACE_DETACH, pid, 0, 0))

@export_func
def syscall(pid):
	return _basic(PTRACE_SYSCALL, pid)

@export_func
def singlestep(pid):
	return _basic(PTRACE_SINGLESTEP, pid)

@export_func
def cont(pid):
	check(ptrace(PTRACE_CONT, pid, 0, 0))

@export_func
def getregs(pid):
	urs = user_regs_struct()
	check(ptrace(PTRACE_GETREGS, pid, 0, ctypes.byref(urs)))
	return urs.to_dict()

@export_func
def setregs(pid, d):
	urs = user_regs_struct.from_dict(d)
	check(ptrace(PTRACE_SETREGS, pid, 0, ctypes.byref(urs)))

@export_func
def get_maps(pid):
	mappings = []
	with open("/proc/%i/maps" % pid) as f:
		data = f.read()
	for line in data.split("\n"):
		if not line:
			continue
		# XXX: Think carefully about if the path contains spaces, or other special characters!
		s = line.split()
		address, flags, offset, device, inode = s[:5]
		path = None
		if len(s) == 6:
			path = s[-1]
		address = [int(x, 16) for x in address.split("-", 1)]
		offset = int(offset, 16)
		inode = int(inode)
		mappings.append({
			"address": address,
			"flags": flags,
			"offset": offset,
			"device": device,
			"inode": inode,
			"path": path,
		})
	return mappings

class Memory:
	def __init__(self, pid):
		self.fd = os.open("/proc/%i/mem" % pid, os.O_RDWR)

	def __getitem__(self, x):
		if isinstance(x, slice):
			assert x.step is None, "Only two-argument slices are supported."
			length = x.stop - x.start
			if length <= 0:
				return ""
			new_pos = os.lseek(self.fd, x.start, os.SEEK_SET)
			assert new_pos == x.start, "Bad lseek on mem read. Got: %r Wanted: %r" % (new_pos, x.start)
			return os.read(self.fd, length)
		return self[x:x+1]

	def __setitem__(self, x, y):
		if isinstance(x, slice):
			assert x.step is None, "Only two argument slices are supported."
			length = x.stop - x.start
			assert isinstance(y, str), "Must assign a string."
			assert len(y) == length, "Length mismatch in memory write."
			new_pos = os.lseek(self.fd, x.start, os.SEEK_SET)
			assert new_pos == x.start, "Bad lseek on mem write. Got: %r Wanted: %r" % (new_pos, x.start)
			bytes_written = os.write(self.fd, y)
			assert bytes_written == len(y), "Bad write on mem. Wrote %r bytes, wanted to write %r" % (bytes_written, len(y))
			return
		self[x:x+len(y)] = y

