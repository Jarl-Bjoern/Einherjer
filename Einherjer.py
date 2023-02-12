#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from os import name as osname
from os.path import dirname, join, realpath
from sys import argv
from subprocess import call

# Arguments
Temp_Args = ""
for _ in argv[1:]:
    Temp_Args += f'{_} '

# Main
if __name__ == '__main__':
    if (osname == 'nt'): call(f'powershell {join(dirname(realpath(__file__)), "Resources/Start_Files/start.ps1")} {Temp_Args}', shell=True)
    else: call(f'sudo bash {join(dirname(realpath(__file__)), "Resources/Start_Files/start.sh")} {Temp_Args}', shell=True)
