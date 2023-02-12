#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from Resources.Header_Files.Libraries import args
from os import name as osname
from os.path import dirname, join, realpath
from subprocess import run

# Main
if __name__ == '__main__':
    if (osname == 'nt'): run(['powershell',f'{join(dirname(realpath(__file__)), "Resources/Start_Files/start.ps1")}',f'{args}'])
    else: run(['sudo','bash',f'{join(dirname(realpath(__file__)), "Resources/Start_Files/start.sh")}',f'{args}'])
