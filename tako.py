#!/usr/bin/env python3
import gdb
import subprocess
import re

class Entry:
	def __init__(self):
		#self.cmd = {"dynamic" : self.dynamic, "sym" : self.dynsym, "str" : self.dynstr, "rela" : self.rela}
		self.cmd = {"dynamic" : self.dynamic}
		self.link_map = Link_map()

	def dynamic(self, l, d_tag):
		if int(l) <= len(self.link_map.map_list) and int(l) > 0:
			if d_tag != "0":
				print(gdb.Value(self.link_map.l_info(l, d_tag)).cast(gdb.lookup_type("Elf64_Dyn").pointer()).dereference())
			else:
				Dyn_base = gdb.Value(self.link_map.map_list[int(l) - 1]).cast(gdb.lookup_type("struct link_map").pointer()).dereference()["l_ld"]
				while gdb.Value(Dyn_base).cast(gdb.lookup_type("Elf64_Dyn").pointer()).dereference()["d_tag"] != 0:
					print(gdb.Value(Dyn_base).cast(gdb.lookup_type("Elf64_Dyn").pointer()).dereference())
					Dyn_base = Dyn_base + 0x1
		else:
			print("no such link_map")

class Link_map:
	def __init__(self):
		self.cmd = {"all" : self.display, "br" : self.detail}
		r_debug = int(gdb.execute("p/x &_r_debug", to_string = True).split()[2], 16) 
		link_map = gdb.Value(r_debug).cast(gdb.lookup_type("struct r_debug").pointer()).dereference()["r_map"]
		self.map_list = []
		while link_map != 0:
			self.map_list.append(link_map)
			link_map = gdb.Value(link_map).cast(gdb.lookup_type("struct link_map").pointer()).dereference()["l_next"]

	def display(self):
		for i in self.map_list:
			print(str(i).split()[0] + ":" + str(gdb.Value(i).cast(gdb.lookup_type("struct link_map").pointer()).dereference()["l_name"]).split()[1])

	def detail(self, l):
		if int(l) <= len(self.map_list) and int(l) > 0:
			print(gdb.Value(self.map_list[int(l) - 1]).cast(gdb.lookup_type("struct link_map").pointer()).dereference())

	def l_info(self, l, d_tag):
		info = {"DT_STRTAB" : 0x5, "DT_SYMTAB" : 0x6, "DT_JMPREL" : 0x17}
		if info.__contains__(d_tag):
			return gdb.Value().cast(gdb.lookup_type("struct link_map").pointer()).dereference()["l_info"][info[d_tag]]
		print("not support yet")
		return None

class Tako(gdb.Command):
	def __init__(self):
		super(Tako, self).__init__("Tako", gdb.COMMAND_USER)
		self.fun = {"link_map" : Link_map, "entry" : Entry}

	def invoke(self, cmd, from_tty):
		arg = cmd.split()
		if self.fun.__contains__(arg[0]) and len(arg) > 1:
			x = self.fun[arg[0]]()
			if x.cmd.__contains__(arg[1]):
				x.cmd[arg[1]](*arg[2:])

Tako()
