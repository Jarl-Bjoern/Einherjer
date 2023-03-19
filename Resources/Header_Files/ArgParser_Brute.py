#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from Resources.Standard_Operations.Colors import Colors
from .Libraries import dirname, join, realpath

# Functions
def Argument_Parser(Template_Location = dirname(realpath(__file__)).replace('Resources/Header_Files', 'Templates')):
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
    auth_arguments        = parser.add_argument_group(Colors.ORANGE+'authentication arguments'+Colors.RESET)
    brute_arguments       = parser.add_argument_group(Colors.ORANGE+'brute-force arguments'+Colors.RESET)
    config_arguments      = parser.add_argument_group(Colors.ORANGE+'config arguments'+Colors.RESET)
    debug_arguments       = parser.add_argument_group(Colors.ORANGE+'debug arguments'+Colors.RESET)
    filter_arguments      = parser.add_argument_group(Colors.ORANGE+'format arguments'+Colors.RESET)
    optional              = parser.add_argument_group(Colors.ORANGE+'optional arguments'+Colors.RESET)
    performance_arguments = parser.add_argument_group(Colors.ORANGE+'performance arguments'+Colors.RESET)
    target_arguments      = parser.add_argument_group(Colors.ORANGE+'target arguments'+Colors.RESET)

    auth_arguments.add_argument('-aBaU', '--add-basic-authentication-user', type=str, help=Colors.GREEN+'This parameter defines the user for basic authentication.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    auth_arguments.add_argument('-aBaP', '--add-basic-authentication-password', type=str, help=Colors.GREEN+'This parameter defines the password for basic authentication.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    auth_arguments.add_argument('-aC', '--add-cert', type=str, help=Colors.GREEN+'This parameter defines the cert file for authentication.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    auth_arguments.add_argument('-aCkf', '--add-cert-key-file', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    auth_arguments.add_argument('-apC', '--add-pkcs12-cert', type=str, help=Colors.GREEN+'This parameter defines the cert file for pkcs12 authentication.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    auth_arguments.add_argument('-aUL', '--add-user-list', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    auth_arguments.add_argument('-aCPw', '--add-cert-password', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    auth_arguments.add_argument('-apCPw', '--add-pkcs12-cert-password', type=str, help=Colors.GREEN+'This parameter defines the password for pkcs12 authentication.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    scan_arguments.add_argument('-bA', '--brute-all', type=bool, nargs='?', const=True, help=Colors.GREEN+'With this it is possible to scan all functions.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    brute_arguments.add_argument('-bC', '--brute-credentials', type=bool, nargs='?', const=True, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    brute_arguments.add_argument('-bDNS', '--brute-dns', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    brute_arguments.add_argument('-bF', '--brute-fuzzing', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    brute_arguments.add_argument('-bFTP', '--brute-ftp', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    brute_arguments.add_argument('-bSNMP', '--brute-snmp', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    brute_arguments.add_argument('-bScR', '--brute-screenshot-recursive', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    brute_arguments.add_argument('-bSMTP', '--brute-smtp', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    brute_arguments.add_argument('-aW', '--add-wordlist', type=str, help=Colors.GREEN+'With this function you add a wordlist for fuzzing.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    brute_arguments.add_argument('-amW', '--add-multiple-wordlists', type=str, help=Colors.GREEN+'This parameter specifies a location with several wordlists which will be checked for\nduplicates and sort them out for fuzzing.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    brute_arguments.add_argument('-6', '--ipv6', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    config_arguments.add_argument('-aHP', '--add-http-proxy', type=str, help=Colors.GREEN+'Specify your HTTP-Proxy.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    config_arguments.add_argument('-aHSP', '--add-https-proxy', type=str, help=Colors.GREEN+'Specify your HTTPS-Proxy.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    config_arguments.add_argument('-aSP', '--add-socks-proxy', type=str, help=Colors.GREEN+'Specify your Socks-Proxy.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    config_arguments.add_argument('-o', '--output-location', type=str, help=Colors.GREEN+'Specify the location where the result should be saved.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    debug_arguments.add_argument('-d', '--debug', type=bool, nargs='?', default=False, help=Colors.GREEN+'This Parameter deactivates the terminal clearing after starting the tool.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    optional.add_argument('-c', '--custom-chromium-path', type=str, help=Colors.GREEN+'Specify the location of your custom chromium.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    optional.add_argument('-h','--help', action='help', default=SUPPRESS, help=Colors.GREEN+'Show this help message and exit.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    performance_arguments.add_argument('-aSt', '--async-ssl-timeout', type=int, default=15, help=Colors.GREEN+'Specify the connection timeout inside the ssl ciphers scan in seconds.\n\nDefault: 15 seconds'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    performance_arguments.add_argument('-fw', '--fuzzing-wait', type=int, default=0.85, help=Colors.GREEN+'This parameter specifies the default sleep between the fuzzing.\n\nDefault: 0.85 Seconds'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    performance_arguments.add_argument('-mx', '--max-connections', type=int, default=5, help=Colors.GREEN+'Defines the max connections for threads and processes.\n\nDefault: 5 Threads'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    performance_arguments.add_argument('-r', '--random-order', type=bool, nargs='?', default=False, help=Colors.GREEN+'This parameter randomize your targets.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    performance_arguments.add_argument('-s', '--sleep', type=float, default=360, help=Colors.GREEN+'Set the pauses between the scans to do not DDoS the target.\n\nDefault: 360 Seconds'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    performance_arguments.add_argument('-sw', '--screenshot-wait', type=int, default=10, help=Colors.GREEN+'This parameter specifies the default waiting time to connect to the target page.\n\nDefault: 10 Seconds'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    performance_arguments.add_argument('-tHo', '--thread-timeout', type=int, default=7200, help=Colors.GREEN+'This parameter sets the max time to wait until a thread will be terminated.\n\nDefault: 7200 Seconds'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    performance_arguments.add_argument('-to', '--timeout', type=int, default=30, help=Colors.GREEN+'Specify the connection http timeout in seconds.\n\nDefault: 30 seconds'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    performance_arguments.add_argument('-ww', '--webdriver-wait', type=int, default=15, help=Colors.GREEN+'This parameter specifies the default waiting time between the screenshots.\n\nDefault: 15 Seconds'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    target_arguments.add_argument('-iL', '--import-list', type=str, help=Colors.GREEN+'Import your target list in the following example:\n  - http://192.168.2.2\n  - https://192.168.2.3\n  - https://192.168.2.4:8443\n  - ssh://192.168.2.5:22\n  - ssl://192.168.2.5:3389'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)    
    target_arguments.add_argument('-t', '--target', type=str, nargs='*', help=Colors.GREEN+'Specify a single or multiple targets like in the following example:\n   - http://127.0.0.1, https://127.0.0.1'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    target_arguments.add_argument('-aNx', '--add-nmap-xml-result', type=str, help=Colors.GREEN+'Import your nmap-xml-results as your targets.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    del ArgumentParser, RawTextHelpFormatter, SUPPRESS
    return parser.parse_args()
