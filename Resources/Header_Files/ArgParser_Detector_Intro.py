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
-------------------------------------------------------------------------------------
"""

    parser = ArgumentParser(add_help=False, formatter_class=RawTextHelpFormatter, description=Colors.ORANGE+Program_Description+Colors.RESET, allow_abbrev=False, usage=SUPPRESS)
    config_arguments      = parser.add_argument_group(Colors.ORANGE+'config arguments'+Colors.RESET)
    debug_arguments       = parser.add_argument_group(Colors.ORANGE+'debug arguments'+Colors.RESET)
    detector_arguments    = parser.add_argument_group(Colors.ORANGE+'format arguments'+Colors.RESET)
    optional              = parser.add_argument_group(Colors.ORANGE+'optional arguments'+Colors.RESET)

    config_arguments.add_argument('-aW', '--add-wordlist', type=str, help=Colors.GREEN+'With this function you add a file with hashes.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    config_arguments.add_argument('-amW', '--add-multiple-wordlists', type=str, help=Colors.GREEN+'This parameter specifies a location with several files which will be checked for\nduplicates and sort them out.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    debug_arguments.add_argument('-d', '--debug', type=bool, nargs='?', default=False, help=Colors.GREEN+'This Parameter deactivates the terminal clearing after starting the tool.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    detector_arguments.add_argument('-dH', '--detect-hash', type=bool, nargs='?', const=True, help=Colors.GREEN+'With this parameter it is possible to detect hashes.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    optional.add_argument('-h','--help', action='help', default=SUPPRESS, help=Colors.GREEN+'Show this help message and exit.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    del ArgumentParser, RawTextHelpFormatter, SUPPRESS
    return parser.parse_args()

    print (Colors.RED+Error_Text+Colors.RESET)
