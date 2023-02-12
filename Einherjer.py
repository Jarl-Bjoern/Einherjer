#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Append_Missing_Module_Paths
from os.path import dirname, join, realpath
from sys import path as SYSTEM_PATH
for _ in ['Filter','Format','Header_Files','Standard_Operations','Workfiles']:
    SYSTEM_PATH.append(join(dirname(realpath(__file__)), f'Resources/{_}'))
del dirname, join, realpath, SYSTEM_PATH

# Libraries
from Header_Files.Threads import *

# Main
if __name__ == '__main__':
    if (osname == 'nt'): run(['powershell',f'{join(dirname(realpath(__file__)), "Resources/Start_Files/start.ps1")}',f'{args}'])
    else: run(['sudo','bash',f'{join(dirname(realpath(__file__)), "Resources/Start_Files/start.sh")}',f'{args}'])
