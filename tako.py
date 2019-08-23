#!/usr/bin/env python3
import gdb
import subprocess
import re

class Function:
	def __init__(self):
		self.cmd = {"all" : self.display, "detail" : self.detail}
		self.link_map = Link_map()
		self.rela_plt = gdb.Value(self.link_map.l_info(0, "DT_JMPREL")).cast(gdb.lookup_type("Elf64_Dyn").pointer()).dereference()["d_un"]["d_val"]
		self.rela_bound = int(gdb.Value(self.link_map.l_info(0, "DT_JMPREL")).cast(gdb.lookup_type("Elf64_Dyn").pointer()).dereference()["d_un"]["d_val"]) + int(gdb.Value(self.link_map.l_info(0, "DT_PLTRELSZ")).cast(gdb.lookup_type("Elf64_Dyn").pointer()).dereference()["d_un"]["d_val"])
		self.rela_size = int(gdb.Value(self.link_map.l_info(0, "DT_RELAENT")).cast(gdb.lookup_type("Elf64_Dyn").pointer()).dereference()["d_un"]["d_val"])
		self.sym_tab = gdb.Value(self.link_map.l_info(0, "DT_SYMTAB")).cast(gdb.lookup_type("Elf64_Dyn").pointer()).dereference()["d_un"]["d_val"]
		self.str_tab = gdb.Value(self.link_map.l_info(0, "DT_STRTAB")).cast(gdb.lookup_type("Elf64_Dyn").pointer()).dereference()["d_un"]["d_val"]
		rela_entry = int(self.rela_plt)
		self.fun = []
		while rela_entry < self.rela_bound:
			self.fun.append(rela_entry)
			rela_entry = rela_entry + self.rela_size
		self.__flag = False

	def display(self):
		self.__flag = True
		for i in range(len(self.fun)):
			addrs = self.detail(i + 1)
			gdb.execute("x/s " + addrs[0])
			print("No." + str(i + 1) ," GOT :", addrs[1], " Rela entry :", addrs[2], " Symbol entry :", addrs[3])

	def detail(self, f):
		if int(f) > len(self.fun) or int(f) <= 0:
			print("no such function")
			return None
		rela_entry = int(self.rela_plt) + self.rela_size * (int(f) - 1)
		sym_index = int(str(gdb.Value(rela_entry).cast(gdb.lookup_type("Elf64_Rela").pointer()).dereference()["r_info"])[:-8], 16)
		sym_entry = int(self.sym_tab) + 0x18 * sym_index
		str_offset = int(gdb.Value(sym_entry).cast(gdb.lookup_type("Elf64_Sym").pointer()).dereference()["st_name"]) + int(self.str_tab)
		if self.__flag:
			got = gdb.Value(rela_entry).cast(gdb.lookup_type("Elf64_Rela").pointer()).dereference()["r_offset"]
			return (str(str_offset), got, hex(rela_entry), hex(sym_entry))
		gdb.execute("set print pretty off")
		gdb.execute("x/s " + str(str_offset))
		print("Elf_Rela : ", str(gdb.Value(rela_entry).cast(gdb.lookup_type("Elf64_Rela").pointer()).dereference()))
		print("Elf_Sym : ", str(gdb.Value(sym_entry).cast(gdb.lookup_type("Elf64_Sym").pointer()).dereference()))
		gdb.execute("set print pretty on")

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
		self.cmd = {"all" : self.display, "detail" : self.detail}
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
		info = {"DT_PLTRELSZ" : 0x2, "DT_STRTAB" : 0x5, "DT_SYMTAB" : 0x6, "DT_RELAENT" : 0x9, "DT_JMPREL" : 0x17}
		if info.__contains__(d_tag):
			return gdb.Value(self.map_list[l]).cast(gdb.lookup_type("struct link_map").pointer()).dereference()["l_info"][info[d_tag]]
		print("not support yet")
		return None

class Tako(gdb.Command):
	def __init__(self):
		super(Tako, self).__init__("Tako", gdb.COMMAND_USER)
		self.fun = {"link_map" : Link_map, "fun" : Function}

	def invoke(self, cmd, from_tty):
		arg = cmd.split()
		if self.fun.__contains__(arg[0]) and len(arg) > 1:
			x = self.fun[arg[0]]()
			if x.cmd.__contains__(arg[1]):
				x.cmd[arg[1]](*arg[2:])

Tako()
