#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from os import name as osname
from os.path import dirname, join, realpath
from Resources.Header_Files.Libraries import *
from sys import argv
from subprocess import call

from argparse import Namespace
print (args)
T = args
BB = vars(T)
print (BB)
Z = Namespace()
print (Z)

# Main
if __name__ == '__main__':
    if (osname == 'nt'): call(['powershell',f'{join(dirname(realpath(__file__)), "Resources/Start_Files/start.ps1")}',f'{vars(args)}'])
    else: call(['sudo','bash',f'{join(dirname(realpath(__file__)), "Resources/Start_Files/start.sh")}',f'{vars(args)}'])
