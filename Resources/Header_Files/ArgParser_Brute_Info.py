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
    brute_arguemnts   = parser.add_argument_group(Colors.ORANGE+'brute-force arguments'+Colors.RESET)
    config_arguments  = parser.add_argument_group(Colors.ORANGE+'config arguments'+Colors.RESET)
    debug_arguments   = parser.add_argument_group(Colors.ORANGE+'debug arguments'+Colors.RESET)
    filter_arguments  = parser.add_argument_group(Colors.ORANGE+'format arguments'+Colors.RESET)
    optional          = parser.add_argument_group(Colors.ORANGE+'optional arguments'+Colors.RESET)

    brute_arguments.add_argument('-test', '--test', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    config_arguments.add_argument('-o', '--output-location', type=str, help=Colors.GREEN+'Specify the location where the result should be saved.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    debug_arguments.add_argument('-d', '--debug', type=bool, nargs='?', default=False, help=Colors.GREEN+'This Parameter deactivates the terminal clearing after starting the tool.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    optional.add_argument('-h','--help', action='help', default=SUPPRESS, help=Colors.GREEN+'Show this help message and exit.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    del ArgumentParser, RawTextHelpFormatter, SUPPRESS
    parser.print_help()

    print (Colors.RED+Error_Text+Colors.RESET)
