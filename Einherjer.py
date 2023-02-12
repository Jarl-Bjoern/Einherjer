#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from os import name as osname
from os.path import dirname, join, realpath
from sys import argv
from subprocess import call

# Main
if __name__ == '__main__':
    if (osname == 'nt'): call(['powershell',f'{join(dirname(realpath(__file__)), "Resources/Start_Files/start.ps1")}',f'{argv[1:]}'])
    else: call(['sudo','bash',f'{join(dirname(realpath(__file__)), "Resources/Start_Files/start.sh")}',f'{argv[1:]}'])
