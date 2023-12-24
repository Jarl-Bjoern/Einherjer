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
    config_arguments      = parser.add_argument_group(Colors.ORANGE+'config arguments'+Colors.RESET)
    debug_arguments       = parser.add_argument_group(Colors.ORANGE+'debug arguments'+Colors.RESET)
    format_arguments      = parser.add_argument_group(Colors.ORANGE+'format arguments'+Colors.RESET)
    optional              = parser.add_argument_group(Colors.ORANGE+'optional arguments'+Colors.RESET)
    performance_arguments = parser.add_argument_group(Colors.ORANGE+'performance arguments'+Colors.RESET)
    scan_arguments        = parser.add_argument_group(Colors.ORANGE+'scan arguments'+Colors.RESET)
    target_arguments      = parser.add_argument_group(Colors.ORANGE+'target arguments'+Colors.RESET)

    auth_arguments.add_argument('-aBaU', '--add-basic-authentication-user', type=str, help=Colors.GREEN+'This parameter defines the user for basic authentication.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    auth_arguments.add_argument('-aBaP', '--add-basic-authentication-password', type=str, help=Colors.GREEN+'This parameter defines the password for basic authentication.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    auth_arguments.add_argument('-aC', '--add-cert', type=str, help=Colors.GREEN+'This parameter defines the cert file for authentication.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    auth_arguments.add_argument('-aCkf', '--add-cert-key-file', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    auth_arguments.add_argument('-apC', '--add-pkcs12-cert', type=str, help=Colors.GREEN+'This parameter defines the cert file for pkcs12 authentication.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    auth_arguments.add_argument('-aUL', '--add-user-list', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    auth_arguments.add_argument('-aCPw', '--add-cert-password', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    auth_arguments.add_argument('-apCPw', '--add-pkcs12-cert-password', type=str, help=Colors.GREEN+'This parameter defines the password for pkcs12 authentication.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    config_arguments.add_argument('-aHP', '--add-http-proxy', type=str, help=Colors.GREEN+'Specify your HTTP-Proxy.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    config_arguments.add_argument('-aHSP', '--add-https-proxy', type=str, help=Colors.GREEN+'Specify your HTTPS-Proxy.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    config_arguments.add_argument('-aSP', '--add-socks-proxy', type=str, help=Colors.GREEN+'Specify your Socks-Proxy.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    config_arguments.add_argument('-aR', '--allow-redirects', type=bool, nargs='?', default=True, help=Colors.GREEN+'This parameter specifies whether forwarding should be used for web requests.\n\nDefault: True'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    config_arguments.add_argument('-o', '--output-location', type=str, help=Colors.GREEN+'Specify the location where the result should be saved.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    config_arguments.add_argument('-rChh', '--read-config-http-header', type=bool, nargs='?', default=True, help=Colors.GREEN+'Use this parameter to specify that the template for the normal server headers are read.\n\nThis value is enabled by default.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    config_arguments.add_argument('-rChhA', '--read-config-http-header-api', type=bool, nargs='?', default=False, help=Colors.GREEN+'Use this parameter to specify that the template for the normal API headers are read.\n\nThis value is disabled by default.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    config_arguments.add_argument('-rChF', '--read-custom-header-file', type=bool, nargs='?', default=False, help=Colors.GREEN+'Use this parameter to specify that the customized header file will be load.\n\nExample:\n  - {"Connection": "Close"}\n\nThis value is disabled by default.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    config_arguments.add_argument('-sMS', '--smtp-mail-sender', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    config_arguments.add_argument('-sMR', '--smtp-mail-receiver', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    config_arguments.add_argument('-sMM', '--smtp-mail-message', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    config_arguments.add_argument('-wSf', '--write-state-file', type=bool, nargs='?', default=True, help=Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    debug_arguments.add_argument('-d', '--debug', type=bool, nargs='?', default=False, help=Colors.GREEN+'This Parameter deactivates the terminal clearing after starting the tool.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    format_arguments.add_argument('-f', '--format', choices=['csv','docx','html','json','md','pdf','tex','xlsx','xml','yaml'], type=str, default='csv', help=Colors.GREEN+'Specify your used format like xlsx (Excel), Docx (MS Word), LaTeX or PDF.'+Colors.RESET+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    format_arguments.add_argument('-dbP', '--database-password', nargs='?', type=bool, default=False, help=Colors.GREEN+'This parameter can be used to set a password for the KeePass database.\n\nDefault: Einherjer'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    format_arguments.add_argument('-sFt', '--screenshot-frame-thickness', nargs='?', type=int, default=5, help=Colors.GREEN+'Using this parameter you can set the thickness of a frame.\n\nDefault: 5'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    format_arguments.add_argument('-zF', '--zip-file', type=bool, nargs='?', default=False, help=Colors.GREEN+'This parameter determines whether your output should be saved to a ZipFile.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    format_arguments.add_argument('-zFp', '--zip-file-password', type=bool, nargs='?', default=False, help=Colors.GREEN+'With this parameter you set the switch so that you can set a password for your zipfile.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    #optional.add_argument('-app', '--append-to-existing-xlsx', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    optional.add_argument('-cDP', '--custom-chromium-path', type=str, default='/usr/bin/chromium', help=Colors.GREEN+'Specify the location of your custom chromium.\n\nDefault: /usr/bin/chromium'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    optional.add_argument('-cWDP', '--custom-chromium-webdriver-path', type=str, default='/usr/bin/chromedriver', help=Colors.GREEN+'Specify the location of your custom chromium webdriver.\n\nDefault: /usr/bin/chromedriver'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    optional.add_argument('-h','--help', action='help', default=SUPPRESS, help=Colors.GREEN+'Show this help message and exit.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    performance_arguments.add_argument('-aSt', '--async-ssl-timeout', type=int, default=15, help=Colors.GREEN+'Specify the connection timeout inside the ssl ciphers scan in seconds.\n\nDefault: 15 seconds'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    performance_arguments.add_argument('-mx', '--max-connections', type=int, default=15, help=Colors.GREEN+'Defines the max connections for threads and processes.\n\nDefault: 15 Threads'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    performance_arguments.add_argument('-mSt', '--max-ssl-targets', type=int, default=15, help=Colors.GREEN+'This parameter sets the maximum number of SSL targets for a thread.\n\nDefault: 15 Targets'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    performance_arguments.add_argument('-ps', '--process-sleep', type=float, default=35, help=Colors.GREEN+'Set the pauses between the process starts to do not DDoS the target.\n\nDefault: 35 Seconds'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    performance_arguments.add_argument('-r', '--random-order', type=bool, nargs='?', default=False, help=Colors.GREEN+'This parameter randomize your targets.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    performance_arguments.add_argument('-s', '--sleep', type=float, default=45, help=Colors.GREEN+'Set the pauses between the scans to do not DDoS the target.\n\nDefault: 45 Seconds'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    performance_arguments.add_argument('-sw', '--screenshot-wait', type=int, default=30, help=Colors.GREEN+'This parameter specifies the default waiting time to connect to the target page.\n\nDefault: 30 Seconds'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    performance_arguments.add_argument('-tHo', '--thread-timeout', type=int, default=360, help=Colors.GREEN+'This parameter sets the max time to wait until a thread will be terminated.\n\nDefault: 360 Seconds'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    performance_arguments.add_argument('-to', '--timeout', type=int, default=45, help=Colors.GREEN+'Specify the connection http timeout in seconds.\n\nDefault: 45 seconds'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    performance_arguments.add_argument('-ww', '--webdriver-wait', type=int, default=20, help=Colors.GREEN+'This parameter specifies the default waiting time between the screenshots.\n\nDefault: 20 Seconds'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    scan_arguments.add_argument('-sA', '--scan-all', type=bool, nargs='?', const=True, help=Colors.GREEN+'With this it is possible to scan all functions.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-sCORS', '--scan-cors', type=bool, nargs='?', const=True, help=Colors.GREEN+'Use this function to check for CORS vulnerabilities.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-sDNS', '--scan-dns', type=bool, nargs='?', const=True, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-sFTP', '--scan-ftp', type=bool, nargs='?', const=True, help=Colors.GREEN+'This parameter can be used to check an FTP server for minor vulnerabilities.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-sHn', '--scan-host-name', type=bool, nargs='?', const=True, help=Colors.GREEN+'With this parameter you can filter out the hostnames.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-sSSF', '--scan-security-flags', type=bool, nargs='?', const=True, help=Colors.GREEN+'With this function you check the cookie flags for vulnerabilities.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-sSc', '--scan-site-certificate', type=bool, nargs='?', const=True, help=Colors.GREEN+'With this function you will check TLS certificates for vulnerabilities.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-sSh', '--scan-site-header', type=bool, nargs='?', const=True, help=Colors.GREEN+'Use this function to check the HTTP headers for useful information and\nmisconfigurations.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-sShm', '--scan-site-http-methods', type=bool, nargs='?', const=True, help=Colors.GREEN+'This parameter checks a web server for any HTTP methods.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-sSs', '--scan-site-screenshot', type=bool, nargs='?', const=True, help=Colors.GREEN+'With this function you can create screenshots of the start pages.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-sSSL', '--scan-site-ssl', type=bool, nargs='?', const=True, help=Colors.GREEN+'With this function you check the TLS/SSL connections for vulnerabilities.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-sSMTP', '--scan-smtp', type=bool, nargs='?', const=True, help=Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-sSNMP', '--scan-snmp', type=bool, nargs='?', const=True, help=Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-sSSH', '--scan-ssh', type=bool, nargs='?', const=True, help=Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-6', '--ipv6', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    target_arguments.add_argument('-iL', '--import-list', type=str, help=Colors.GREEN+'Import your target list in the following example:\n  - http://192.168.2.2\n  - https://192.168.2.3\n  - https://192.168.2.4:8443\n  - ssh://192.168.2.5:22\n  - ssl://192.168.2.5:3389'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)    
    target_arguments.add_argument('-t', '--target', type=str, nargs='*', help=Colors.GREEN+'Specify a single or multiple targets like in the following example:\n   - http://127.0.0.1, https://127.0.0.1'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    target_arguments.add_argument('-aNx', '--add-nmap-xml-result', type=str, help=Colors.GREEN+'Import your nmap-xml-results as your targets.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    del ArgumentParser, RawTextHelpFormatter, SUPPRESS
    return parser.parse_args()
