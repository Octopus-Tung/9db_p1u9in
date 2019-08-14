#!/usr/bin/env python3
import gdb
import subprocess
import re

class Entry:

    def dyn(self, dyn_base, d_tag):
        while gdb.Value(dyn_base).cast(gdb.lookup_type("Elf64_Dyn").pointer()).dereference()["d_tag"] != d_type:
            Dyn_ptr = dyn_base + 0x10
        return int(gdb.Value(dyn_base).cast(gdb.lookup_type("Elf64_Dyn").pointer()).dereference()["d_un"]["d_ptr"], 16)

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

    def detail(self, index):
        if int(index) <= len(self.map_list) and int(index) > 0:
            print(gdb.Value(self.map_list[int(index) - 1]).cast(gdb.lookup_type("struct link_map").pointer()).dereference())

    def l_info(self, index, dt):
        info = {"STRTAB" : 0x5, "SYMTAB" : 0x6, "JMPREL" : 0x17}
        if info.__contains__(dt):
            return int(gdb.Value().cast(gdb.lookup_type("struct link_map").pointer()).dereference()["l_info"][info.get(dt)], 16)
        else:
            print("not implement yet")
            return None

class Tako(gdb.Command):
    def __init__(self):
        super(Tako, self).__init__("Tako", gdb.COMMAND_USER)
        self.fun = {"link_map" : Link_map}

    def invoke(self, cmd, from_tty):
        arg = cmd.split()
        if self.fun.__contains__(arg[0]) and len(arg) > 1:
            x = self.fun[arg[0]]()
            if x.cmd.__contains__(arg[1]):
                x.cmd[arg[1]](*arg[2:])

Tako()
