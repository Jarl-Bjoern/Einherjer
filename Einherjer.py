#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from os import name as osname
from os.path import dirname, join, realpath
#from Resources.Header_Files.Libraries import *
from sys import argv
from subprocess import call

# Arguments
Temp_Args = ""
for _ in argv[1:]:
    Temp_Args += f'{_} '
print ("__"+Temp_Args+"__")

# Main
if __name__ == '__main__':
    if (osname == 'nt'): call(['powershell',f'{join(dirname(realpath(__file__)), "Resources/Start_Files/start.ps1")}',f'{Temp_Args}'])
    else: call(['sudo','bash',f'{join(dirname(realpath(__file__)), "Resources/Start_Files/start.sh")}',f'{Temp_Args}'])
