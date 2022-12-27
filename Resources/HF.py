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
    from datetime import datetime
    from multiprocessing import active_children, cpu_count, Process, Queue
    from numpy import array
    from os import getcwd, listdir, makedirs, name as osname, remove, system, walk
    from os.path import dirname, exists, join, realpath
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
except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")

class Colors:
    CYAN = '\033[36m'
    GREEN = '\033[32m'
    ORANGE = '\033[33m'
    BLUE = '\033[34m'
    RED = '\033[31m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

# Argument_Parser
from Resources.ArgParser import Argument_Parser
args = Argument_Parser()
del Argument_Parser

# Scanning_Module_Filtering
if (args.scan_all == False and args.scan_site_screenshot == False and args.scan_site_ssl == False and args.scan_site_header == False and args.scan_site_fuzzing == False and args.scan_ssh == False and args.scan_site_screenshot_recursive == False and args.scan_security_flags == False): Module_Error('The scanning method is missing!\n')
elif (args.scan_all != False and args.scan_site_screenshot == False and args.scan_site_ssl == False and args.scan_site_header == False and args.scan_site_fuzzing == False and args.scan_ssh == False and args.scan_site_screenshot_recursive == False and args.scan_security_flags == False):
    try:
        from contextlib import redirect_stdout
        from cv2 import countNonZero, imread, imwrite, rectangle, split as cvsplit, subtract
        from selenium import webdriver
        from selenium.webdriver.common.by import By
        from selenium.webdriver.common.keys import Keys
        from selenium.webdriver.chrome.service import Service
        from selenium.webdriver.remote.webdriver import WebDriver
        from webbrowser import open as webbrowser_open
        with redirect_stdout(None):
           from webdriver_manager.chrome import ChromeDriverManager
        from asyncssh import Error as AsyncSSHError, get_server_auth_methods, SSHClient, SSHClientConnection
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from paramiko.transport import Transport
        from requests import get, Session
        from socket import create_connection
        import asyncio
    except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")
elif (args.scan_all == False):
    try:
        if (args.scan_site_screenshot != False):
            from contextlib import redirect_stdout
            from cv2 import countNonZero, imread, imwrite, rectangle, split as cvsplit, subtract
            from selenium import webdriver
            from selenium.webdriver.common.by import By
            from selenium.webdriver.common.keys import Keys
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
            from paramiko.transport import Transport
            import asyncio
        if (args.scan_security_flags != False):
            from requests import Session
    except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")
