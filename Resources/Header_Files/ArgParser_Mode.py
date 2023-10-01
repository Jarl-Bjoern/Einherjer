#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from Resources.Standard_Operations.Colors import Colors
from .Libraries import dirname, join, realpath

# Functions
def Argument_Parser(Error_Text, Template_Location = dirname(realpath(__file__)).replace('Resources/Header_Files', 'Templates')):
    from argparse import ArgumentParser, RawTextHelpFormatter, SUPPRESS

    Program_Description = """-------------------------------------------------------------------------------------
|  Rainer Christian Bjoern Herold                                                   |
|  Copyright 2022-2023. All rights reserved.                                        |
|                                                                                   |
|  Please do not use the program for illegal activities.                            |
|                                                                                   |
|  If you got any problems don't hesitate to contact me so I can try to fix them.   |
|                                                                                   |
|  If you use the "Kali-Last-Snapshot" repository, you might install a slightly     |
|  older driver of Chromium with the command "apt install -y chromium". If this     |
|  is the case, then you should check after the installation with the command       |
|  "apt-cache policy chromium" which version was installed and then download the    |
|  appropriate Chrome Webdriver from the following page                             |
|  "https://chromedriver.chromium.org/downloads" and replace it instead.            |
|                                                                                   |
|  In some cases it can happen that after an installation of Chromium, the program  |
|  cannot create processes, because no environment variable for the Chromedriver    |
|  can be accessed, therefore the system must be restarted once.                    |
-------------------------------------------------------------------------------------
"""

    parser = ArgumentParser(add_help=False, formatter_class=RawTextHelpFormatter, description=Colors.ORANGE+Program_Description+Colors.RESET, allow_abbrev=False, usage=SUPPRESS)
    program_arguments = parser.add_argument_group(Colors.ORANGE+'program arguments'+Colors.RESET)

    program_arguments.add_argument('--brute-force-mode', type=bool, nargs='?', default=False, help=Colors.GREEN+'UNDER CONSTRUCTION\n'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    program_arguments.add_argument('--community-mode', type=bool, nargs='?', default=False, help=Colors.GREEN+'UNDER CONSTRUCTION\n'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    program_arguments.add_argument('--filter-mode', type=bool, nargs='?', default=False, help=Colors.GREEN+'This parameter is used to use the filter mode.\n\nExample:\n  - python3 Einherjer.py --filter-mode\n'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    program_arguments.add_argument('--fuzzing-mode', type=bool, nargs='?', default=True, help=Colors.GREEN+'UNDER CONSTRUCTION\n'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    program_arguments.add_argument('--generator-mode', type=bool, nargs='?', default=False, help=Colors.GREEN+'UNDER CONSTRUCTION\n'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    program_arguments.add_argument('--scanning-mode', type=bool, nargs='?', default=True, help=Colors.GREEN+'This parameter is used to use the scanning mode.\n\nExample:\n  - python3 Einherjer.py --scanning-mode\n'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
#    program_arguments.add_argument('--program-cmd', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
#    program_arguments.add_argument('--program-server', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    del ArgumentParser, RawTextHelpFormatter, SUPPRESS
    parser.print_help()

    print (Colors.RED+Error_Text+Colors.RESET)
