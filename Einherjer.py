#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold
# Vers 0.1 30.05.2022
# Vers 0.2 06.06.2022
# Vers 0.3 09.06.2022
# Vers 0.4 13.06.2022
# Vers 0.5 02.08.2022
# Vers 0.6 23.08.2022
# Vers 0.7 20.09.2022

# Author
__author__      = "Rainer Christian Bjoern Herold"
__copyright__   = "Copyright 2022-2023, Rainer Christian Bjoern Herold"
__credits__     = "Rainer Christian Bjoern Herold"
__license__     = "MIT license"
__version__     = "0.8"
__maintainer__  = "Rainer Christian Bjoern Herold"
__status__      = "Production"

# Libraries
from os         import name as osname
from os.path    import dirname, join, realpath
from sys        import argv
from subprocess import call

# Filter_Proxychains
if (osname != 'nt'):
    if ("proxychains" in argv and not "proxychains4" in argv):
        Switch_Proxychains  = True
        argv.remove("proxychains")
    elif ("proxychains" not in argv and "proxychains4" in argv):
        Switch_Proxychains_Four = True
        argv.remove("proxychains4")

# Arguments
Temp_Args = ""
for _ in argv[1:]:
    Temp_Args += f'{_} '

# Main
if __name__ == '__main__':
    if (osname == 'nt'): call(f'powershell {join(dirname(realpath(__file__)), "Resources/Start_Files/start.ps1")} {Temp_Args}', shell=True)
    else:                call(f'sudo bash {join(dirname(realpath(__file__)), "Resources/Start_Files/start.sh")} {Temp_Args}', shell=True)
