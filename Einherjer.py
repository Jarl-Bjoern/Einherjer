#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from Resources.Header_Files.Threads import *

# Main
if __name__ == '__main__':
    if (osname == 'nt'): system(f'powershell {join(dirname(realpath(__file__)), "Resources/Start_Files/start.ps1")} {args}')
    else: system(f'sudo bash {join(dirname(realpath(__file__)), "Resources/Start_Files/start.sh")} {args}')
