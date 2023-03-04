#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Standard_Operations.Colors import Colors
from .Libraries import dirname, join, realpath

# Functions
def Argument_Parser(Error_Text, Template_Location = dirname(realpath(__file__)).replace('Resources/Header_Files', 'Templates')):
    from argparse import ArgumentParser, RawTextHelpFormatter, SUPPRESS

    Program_Description = """-------------------------------------------------------------------------------------
|  Rainer Christian Bjoern Herold                                                   |
|  Copyright 2022-2023. All rights reserved.                                        |
|                                                                                   |
|  Please do not use the program for illegal activities.                            |
-------------------------------------------------------------------------------------
"""

    parser = ArgumentParser(add_help=False, formatter_class=RawTextHelpFormatter, description=Colors.ORANGE+Program_Description+Colors.RESET, allow_abbrev=False, usage=SUPPRESS)
    scan_arguments = parser.add_argument_group(Colors.ORANGE+'scan arguments'+Colors.RESET)
    target_arguments = parser.add_argument_group(Colors.ORANGE+'target arguments'+Colors.RESET)

    #scan_arguments.add_argument('-sArg', '--scan-arguments', choices=['all','dns-fuzzing','http-credentials','http-cookie-security','http-fuzzing','http-header','http-header-api','http-screenshot','http-screenshot-recursive','http-ssl', 'ssh'], type=str, nargs='+', help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    #scan_arguments.add_argument('-sA', '--scan-all', type=bool, nargs='?', const=True, help=Colors.GREEN+'With this it is possible to scan all functions.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    #scan_arguments.add_argument('-sSdbr', '--scan-site-dns-bruteforce', type=bool, nargs='?', const=True, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-sSs', '--scan-site-screenshot', type=bool, nargs='?', const=True, help=Colors.GREEN+'With this function you can create screenshots of the start pages.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-sSc', '--scan-site-certificate', type=bool, nargs='?', const=True, help=Colors.GREEN+'With this function you will check TLS certificates for vulnerabilities.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    #scan_arguments.add_argument('-sSsr', '--scan-site-screenshot-recursive', type=bool, nargs='?', const=True, help=Colors.GREEN+'With this function you can create screenshots of the target pages,\nbut with the special feature that any results are checked with the fuzzing\nand screenshots are created from them in each case.'+Colors.RESET+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-sSSL', '--scan-site-ssl', type=bool, nargs='?', const=True, help=Colors.GREEN+'With this function you check the TLS/SSL connections for vulnerabilities.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-sSh', '--scan-site-header', type=bool, nargs='?', const=True, help=Colors.GREEN+'Use this function to check the HTTP headers for useful information and\nmisconfigurations.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    #scan_arguments.add_argument('-sSF', '--scan-site-fuzzing', type=bool, nargs='?', const=True, help=Colors.GREEN+'With this function you check the web services for hidden directories or files.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    #scan_arguments.add_argument('-sSSH', '--scan-ssh', type=bool, nargs='?', const=True, help=Colors.GREEN+'With this function you check the SSH service for vulnerabilities.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-sSSF', '--scan-security-flags', type=bool, nargs='?', const=True, help=Colors.GREEN+'With this function you check the cookie flags for vulnerabilities.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    #scan_arguments.add_argument('-sC', '--scan-credentials', type=bool, nargs='?', const=True, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    #scan_arguments.add_argument('-aNr', '--add-nmap-ssh-result', type=str, help=Colors.GREEN+'With this function you analyze the ssh output of nmap.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    #scan_arguments.add_argument('-aW', '--add-wordlist', type=str, help=Colors.GREEN+'With this function you add a wordlist for fuzzing.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    #scan_arguments.add_argument('-amW', '--add-multiple-wordlists', type=str, help=Colors.GREEN+'This parameter specifies a location with several wordlists which will be checked for\nduplicates and sort them out for fuzzing.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    #scan_arguments.add_argument('-6', '--ipv6', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    target_arguments.add_argument('-iL', '--import-list', type=str, help=Colors.GREEN+'Import your target list in the following example:\n  - http://192.168.2.2\n  - https://192.168.2.3\n  - https://192.168.2.4:8443\n  - ssh://192.168.2.5:22\n  - ssl://192.168.2.5:3389'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)    
    target_arguments.add_argument('-t', '--target', type=str, nargs='*', help=Colors.GREEN+'Specify a single or multiple targets like in the following example:\n   - 127.0.0.1, http://127.0.0.1, https://127.0.0.1'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    del ArgumentParser, RawTextHelpFormatter, SUPPRESS
    parser.print_help()

    print (Colors.RED+Error_Text+Colors.RESET)
