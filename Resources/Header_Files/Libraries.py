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
__author__ = "Rainer Christian Bjoern Herold"
__copyright__ = "Copyright 2022-2023, Rainer Christian Bjoern Herold"
__credits__ = "Rainer Christian Bjoern Herold"
__license__ = "MIT license"
__version__ = "0.7"
__maintainer__ = "Rainer Christian Bjoern Herold"
__status__ = "Production"

# Base_Function
def Module_Error(Text):
    input(Text), exit()

# Libraries
try:
    from contextlib import redirect_stdout
    from datetime import datetime
    from multiprocessing import active_children, Process, Queue
    from numpy import array
    from os import chmod, getcwd, listdir, makedirs, name as osname, remove, system, walk
    from os.path import dirname, exists, join, realpath
    from pathlib import Path
    from requests.exceptions import *
    from re import search, split as resplit
    from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TimeElapsedColumn, TimeRemainingColumn
    from selenium.common.exceptions import *
    from socket import gaierror, gethostbyaddr, gethostbyname, herror, setdefaulttimeout
    from ssl import cert_time_to_seconds, create_default_context, _create_unverified_context as create_unverified_context, get_server_certificate
    from subprocess import getoutput
    from sys import stdout
    from time import sleep, strftime, time
    from threading import Thread, enumerate as Th_enumerate
    from traceback import print_exc
    from urllib3 import disable_warnings
    from urllib3.exceptions import *
    from warnings import catch_warnings, simplefilter
    import stat
    with catch_warnings():
        simplefilter("ignore")
        from paramiko.ssh_exception import SSHException
except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")

# Argument_Parser
from Resources.Header_Files.ArgParser import Argument_Parser
args = Argument_Parser()

# Scanning_Filter
from Resources.Colors import Colors
def Scanning_Error():
    print('The scanning method is missing!\n\n')
    print('-sA, --scan-all\t\t'+Colors.GREEN+'With this it is possible to scan all functions'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    print('-sSdbr, --scan-site-dns-bruteforce\t\t'+Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    print('-sSs, --scan-site-screenshot\t\t'+Colors.GREEN+'With this function you can create screenshots of the start pages.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    print('-sSsr, --scan-site-screenshot-recursive\t\t'+Colors.GREEN+'With this function you can create screenshots of the target pages,\nbut with the special feature that any results are checked with the fuzzing\nand screenshots are created from them in each case.'+Colors.RESET+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    print('-sSSL, --scan-site-ssl\t\t'+Colors.GREEN+'With this function you check the TLS/SSL connections for vulnerabilities.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    print('-sSh, --scan-site-header\t\t'+Colors.GREEN+'Use this function to check the HTTP headers for useful information and\nmisconfigurations.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    print('-sSF, --scan-site-fuzzing\t\t'+Colors.GREEN+'With this function you check the web services for hidden directories or files.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    print('-sSSH, --scan-ssh\t\t'+Colors.GREEN+'With this function you check the SSH service for vulnerabilities.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    print('-sSSF, --scan-security-flags\t\t'+Colors.GREEN+'With this function you check the cookie flags for vulnerabilities.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    print('-sC, --scan-credentials\t\t'+Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    exit()

# Scanning_Module_Filtering
if (args.scan_all == False and args.scan_site_screenshot == False and args.scan_site_ssl == False and args.scan_site_header == False and args.scan_site_fuzzing == False and args.scan_ssh == False and args.scan_site_screenshot_recursive == False and args.scan_security_flags == False):
    Module_Error("The scanning method is missing!\n\n")
elif (args.scan_all != False and args.scan_site_screenshot == False and args.scan_site_ssl == False and args.scan_site_header == False and args.scan_site_fuzzing == False and args.scan_ssh == False and args.scan_site_screenshot_recursive == False and args.scan_security_flags == False):
    try:
        from cv2 import countNonZero, imread, imwrite, rectangle, split as cvsplit, subtract
        from os import environ, rename
        from selenium import webdriver
        from selenium.webdriver.common.by import By
        from selenium.webdriver.common.keys import Keys
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
        from selenium.webdriver.remote.webdriver import WebDriver
        from webbrowser import open as webbrowser_open
        with catch_warnings():
            simplefilter("ignore")
            from paramiko.transport import Transport
        with redirect_stdout(None):
            from webdriver_manager.chrome import ChromeDriverManager
        from asyncssh import Error as AsyncSSHError, get_server_auth_methods, SSHClient, SSHClientConnection
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from requests import get, Session
        from socket import create_connection
        import asyncio
    except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")
elif (args.scan_all == False):
    try:
        if (args.scan_site_screenshot != False):
            from cv2 import countNonZero, imread, imwrite, rectangle, split as cvsplit, subtract
            from os import environ, rename
            from selenium import webdriver
            from selenium.webdriver.common.by import By
            from selenium.webdriver.common.keys import Keys
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.chrome.service import Service
            from selenium.webdriver.remote.webdriver import WebDriver
            from webbrowser import open as webbrowser_open
            with redirect_stdout(None):
               from webdriver_manager.chrome import ChromeDriverManager
        if (args.scan_site_ssl != False):
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            from socket import create_connection
        if (args.scan_site_header != False or args.scan_site_fuzzing != False):
            from requests import get
        if (args.scan_ssh != False):
            from asyncssh import Error as AsyncSSHError, get_server_auth_methods, SSHClient, SSHClientConnection
            with catch_warnings():
                simplefilter("ignore")
                from paramiko.transport import Transport
            import asyncio
        if (args.scan_security_flags != False):
            from requests import Session
    except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")

# Change_Permissions_For_Webdriver
for _ in listdir(dirname(realpath(__file__)).replace('Header_Files', 'Webdriver')):
    temp_file = Path(join(dirname(realpath(__file__)).replace('Header_Files', 'Webdriver'), _))
    temp_file.chmod(temp_file.stat().st_mode | stat.S_IEXEC)

# Delete_Unused_Functions
del Argument_Parser, catch_warnings, chmod, Path, redirect_stdout, simplefilter, stat, temp_file

# Static_Date
Date = strftime('%Y-%m-%d_%H-%M-%S')
