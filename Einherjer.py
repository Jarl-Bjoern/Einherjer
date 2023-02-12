#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Define_Module_Path
from os.path import dirname, join, realpath
from sys import path as SYSTEM_PATH
SYSTEM_PATH.append(join(dirname(realpath(__file__)), "Resources"))

# Libraries
from Resources.Header_Files.Libraries import args
from os import name as osname
from subprocess import run

# Main
if __name__ == '__main__':
    if (osname == 'nt'): run(['powershell',f'{join(dirname(realpath(__file__)), "Resources/Start_Files/start.ps1")}',f'{args}'])
    else: run(['sudo','bash',f'{join(dirname(realpath(__file__)), "Resources/Start_Files/start.sh")}',f'{args}'])
