import gdb
import subprocess
import re

class Entry:

	def dyn(self, dyn_base, d_tag):
		while gdb.Value(dyn_base).cast(gdb.lookup_type("Elf64_Dyn").pointer()).dereference()["d_tag"] != d_type:
			Dyn_ptr = dyn_base + 0x10
		return gdb.Value(dyn_base).cast(gdb.lookup_type("Elf64_Dyn").pointer()).dereference()["d_un"]["d_ptr"]

class Link_map:
	def __init__(self):
		r_debug = int(gdb.execute("p/x &_r_debug", to_string = True).split()[2], 16) 
		link_map = gdb.Value(r_debug).cast(gdb.lookup_type("struct r_debug").pointer()).dereference()["r_map"]
		self.map_list = []
		while link_map != 0:
			self.map_list.append(link_map)
			link_map = gdb.Value(link_map).cast(gdb.lookup_type("struct link_map").pointer()).dereference()["l_next"]
	
	def display(self, x):
		for i in self.map_list:
			print(str(i).split()[0] + ":" + str(gdb.Value(i).cast(gdb.lookup_type("struct link_map").pointer()).dereference()["l_name"]).split()[1])

	def detail(self, index):
		if int(index) <= len(self.map_list) and int(index) > 0:
			print(gdb.Value(self.map_list[int(index) - 1]).cast(gdb.lookup_type("struct link_map").pointer()).dereference())

	def l_info(self, dt):
		info = {"STRTAB" : 0x5, "SYMTAB" : 0x6, "JMPREL" : 0x17}
		if info.__contains__(dt):
			return int(gdb.Value().cast(gdb.lookup_type("struct link_map").pointer()).dereference()["l_info"][info.get(dt)], 16)
		else:
			print("not implement yet")
			return None

class Tako(gdb.Command):
	def __init__(self):
		super(Tako, self).__init__("Tako", gdb.COMMAND_USER)

	def invoke(self, args, from_tty):
		arg = args.split()
		if arg[0] == "link_map" and len(arg) >= 2:
			l = Link_map()
			arg_dict = {"all" : l.display, "br" : l.detail}
			if arg_dict.__contains__(arg[1]):
				arg_dict[arg[1]](1)
		#if arg[0] == "symbol" and len(arg) == 2:
		#	self.symbol(arg[1])

Tako()
