#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from Resources.Standard_Operations.Colors import Colors
from .Libraries import dirname, join, realpath

# Functions
def Argument_Parser(Copyright_Year, Template_Location = dirname(realpath(__file__)).replace('Resources/Header_Files', 'Templates')):
    from argparse import ArgumentParser, RawTextHelpFormatter, SUPPRESS

    Program_Description = f"""-------------------------------------------------------------------------------------
|  Rainer Christian Bjoern Herold                                                   |
|  Copyright {Copyright_Year}. All rights reserved.                                        |
|                                                                                   |
|  Please do not use the program for illegal activities.                            |
|                                                                                   |
|  If you got any problems don't hesitate to contact me so I can try to fix them.   |
-------------------------------------------------------------------------------------
"""

    parser = ArgumentParser(add_help=False, formatter_class=RawTextHelpFormatter, description=Colors.ORANGE+Program_Description+Colors.RESET, allow_abbrev=False, usage=SUPPRESS)
    config_arguments    = parser.add_argument_group(Colors.ORANGE+'config arguments'+Colors.RESET)
    debug_arguments     = parser.add_argument_group(Colors.ORANGE+'debug arguments'+Colors.RESET)
    filter_arguments    = parser.add_argument_group(Colors.ORANGE+'format arguments'+Colors.RESET)
    nmap_arguments      = parser.add_argument_group(Colors.ORANGE+'nmap arguments'+Colors.RESET)
    picture_arguments   = parser.add_argument_group(Colors.ORANGE+'picture arguments'+Colors.RESET)
    responder_arguments = parser.add_argument_group(Colors.ORANGE+'responder arguments'+Colors.RESET)
    optional            = parser.add_argument_group(Colors.ORANGE+'optional arguments'+Colors.RESET)

    config_arguments.add_argument('-o', '--output-location', type=str, help=Colors.GREEN+'Specify the location where the result should be saved.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    debug_arguments.add_argument('-d', '--debug', type=bool, nargs='?', default=False, help=Colors.GREEN+'This Parameter deactivates the terminal clearing after starting the tool.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    filter_arguments.add_argument('-fS', '--file-split', type=str, help=Colors.GREEN+'This parameter splits a destination file by exactly half the words.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    filter_arguments.add_argument('-hnTf', '--hostname-template-file', type=str, help=Colors.GREEN+'With this argument you load the template for the hostnames.\n\nMake sure that it has the following format:\n127.0.0.1:localhost\n\n       or\n\n127.0.0.1=localhost'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    filter_arguments.add_argument('-hnT', '--hostname-target-file', type=str, help=Colors.GREEN+'With this argument you load the target file, which consists only of IP addresses,\nin order to be able to use the filter for the hostnames.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    nmap_arguments.add_argument('-nC', '--nmap-cookie-scan-location', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    nmap_arguments.add_argument('-nH', '--nmap-header-scan-location', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    nmap_arguments.add_argument('-nSSH', '--nmap-ssh-output-location', type=str, help=Colors.GREEN+'With this parameter you can include nmap files with SSH results, which are\nfiltered and then output as a CSV file.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    nmap_arguments.add_argument('-nSMB', '--nmap-smb-output-location', type=str, help=Colors.GREEN+'With this parameter you can include nmap files with SMB results, which are\nfiltered and then output as a CSV file.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    nmap_arguments.add_argument('-nS', '--nmap-service-scan-file-location', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    nmap_arguments.add_argument('-nU', '--nmap-main-file-location', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    picture_arguments.add_argument('-qA', '--qrcode-picture-location', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    picture_arguments.add_argument('-sL', '--screenshot-location', type=str, help=Colors.GREEN+'Using this parameter you can specify a folder with screenshots, which will be\nloaded into the filter mode and all screenshots in it will be decorated with a\nblack frame.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    picture_arguments.add_argument('-sFt', '--screenshot-frame-thickness', type=int, default=5, help=Colors.GREEN+'Using this parameter you can set the thickness of a frame.\n\nDefault: 5'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    responder_arguments.add_argument('-rLL', '--responder-logs-location', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    optional.add_argument('-h','--help', action='help', default=SUPPRESS, help=Colors.GREEN+'Show this help message and exit.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    del ArgumentParser, RawTextHelpFormatter, SUPPRESS
    return parser.parse_args()
