import gdb
import subprocess
import re

def procmaps():
	pid = re.search("process.*", gdb.execute("info proc exe", to_string = True))
	if pid:
		with open("/proc/" + pid.group().split()[1] + "/maps", "r") as f:
			return f.read()
	else:
		return "AOA"

def fullpath(ELF_name):
	path = re.search(".*" + ELF_name, gdb.execute("info sharedlibrary", to_string = True)).group().split()
	return path[len(path) - 1]

def ELFbase(ELF_name):
	print(re.search(".*" + ELF_name, procmaps()))
	return re.search(".*" + ELF_name, procmaps()).group().split("-")[0]

def section_base(ELF_path, sec_name):
	return re.search(".*" + sec_name + ".*", subprocess.check_output("readelf -S " + ELF_path, shell = True).decode('utf8')).group().split()[3]

def Dyn_entry(ELF_path, d_type, mem):
	if mem:
		Dyn_ptr = int(section_base(ELF_path, "\.dynamic"), 16)
		while gdb.Value(Dyn_ptr).cast(gdb.lookup_type("Elf64_Dyn").pointer()).dereference()["d_tag"] != d_type:
			Dyn_ptr = Dyn_ptr + 0x10
		return gdb.Value(Dyn_ptr).cast(gdb.lookup_type("Elf64_Dyn").pointer()).dereference()["d_un"]["d_ptr"]
	else:
		return re.search(".*" + d_type + ".*", subprocess.check_output("readelf -d " + ELF_path, shell = True).decode('utf8')).group().split()[2]

class Tako(gdb.Command):

	def __init__(self):
		super(Tako, self).__init__("Tako", gdb.COMMAND_USER)

	def link_map(self, arg):
		main_ELF = re.search("exe.*", gdb.execute("info proc exe", to_string = True)).group().split("'")[1]
		#DT_DEBUG
		r_debug = Dyn_entry(main_ELF, 0x15, 1)
		link_map = gdb.Value(r_debug).cast(gdb.lookup_type("struct r_debug").pointer()).dereference()["r_map"]
		link_map_list = []
		while link_map != 0:
			link_map_list.append(link_map)
			link_map = gdb.Value(link_map).cast(gdb.lookup_type("struct link_map").pointer()).dereference()["l_next"]
		if arg == "list":
			for i in link_map_list:
				print(str(i).split()[0] + ":" + str(gdb.Value(i).cast(gdb.lookup_type("struct link_map").pointer()).dereference()["l_name"]).split()[1])
		elif int(arg) <= len(link_map_list) and int(arg) > 0:
			print(str(gdb.Value(link_map_list[int(arg) - 1]).cast(gdb.lookup_type("struct link_map").pointer()).dereference()))

	def invoke(self, args, from_tty):
		arg = args.split()
		if arg[0] == "link_map" and len(arg) == 2:
			self.link_map(arg[1])

Tako()
