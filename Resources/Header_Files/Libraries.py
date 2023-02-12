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

# Define_Module_Path
from os.path import dirname, realpath
from sys import path as SYSTEM_PATH
SYSTEM_PATH.append(dirname(realpath(__file__)).split('Header_Files')[0])

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
    from subprocess import getoutput, run
    from sys import stdout
    from time import sleep, strftime, time
    from threading import Thread, enumerate as Th_enumerate
    from traceback import print_exc
    from urllib3 import disable_warnings
    from urllib3.exceptions import *
    from urllib.parse import quote_plus as html_encode, unquote_plus as html_decode
    from warnings import catch_warnings, simplefilter
    import stat
    with catch_warnings():
        simplefilter("ignore")
        from paramiko.ssh_exception import SSHException

    # Argument_Parser
    from .ArgParser import Argument_Parser
    args = Argument_Parser()

    # Scanning_Module_Filtering
    if (args.scan_all == False and args.scan_site_certificate == False and args.scan_smtp == False and args.scan_site_http_methods == False and args.scan_site_screenshot == False and args.scan_site_ssl == False and args.scan_site_header == False and args.scan_site_fuzzing == False and args.scan_ssh == False and args.scan_site_screenshot_recursive == False and args.scan_security_flags == False):
        from .ArgParser_Intro import Argument_Parser
        Argument_Parser("\n\n\t\t\t\t\tThe scanning method is missing!\n\t\t\t    For more information use the parameter -h or --help.\n"), exit()
    elif (args.scan_all != False and args.scan_site_certificate == False and args.scan_smtp == False and args.scan_site_http_methods == False and args.scan_site_screenshot == False and args.scan_site_ssl == False and args.scan_site_header == False and args.scan_site_fuzzing == False and args.scan_ssh == False and args.scan_site_screenshot_recursive == False and args.scan_security_flags == False):
        from asyncssh import Error as AsyncSSHError, get_server_auth_methods, SSHClient, SSHClientConnection
        from cryptography.x509 import load_der_x509_certificate
        from cryptography.hazmat.backends import default_backend
        from cv2 import countNonZero, imread, imwrite, rectangle, split as cvsplit, subtract
        from http.client import HTTPSConnection
        from os import environ, rename
        from requests import get, Session
        from selenium import webdriver
        from selenium.webdriver.common.by import By
        from selenium.webdriver.common.keys import Keys
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
        from selenium.webdriver.remote.webdriver import WebDriver
        from smtplib import SMTP
        from socket import create_connection
        from webbrowser import open as webbrowser_open
        import asyncio
        with catch_warnings():
            simplefilter("ignore")
            from paramiko.transport import Transport
        with redirect_stdout(None):
            from webdriver_manager.chrome import ChromeDriverManager
    elif (args.scan_all == False):
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
        if (args.scan_site_ssl != False or args.scan_site_certificate != False):
            from cryptography.x509 import load_der_x509_certificate
            from cryptography.hazmat.backends import default_backend
            from socket import create_connection
        if (args.scan_site_header != False or args.scan_site_fuzzing != False):
            from requests import get
        if (args.scan_ssh != False):
            from asyncssh import Error as AsyncSSHError, get_server_auth_methods, SSHClient, SSHClientConnection
            import asyncio
            with catch_warnings():
                simplefilter("ignore")
                from paramiko.transport import Transport
        if (args.scan_security_flags != False):
            from requests import Session
        if (args.scan_site_http_methods != False):
            from http.client import HTTPSConnection
        if (args.scan_smtp != False):
            from smtplib import SMTP
except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")

# Change_Permissions_For_Webdriver
for _ in listdir(dirname(realpath(__file__)).replace('Header_Files', 'Webdriver')):
    temp_file = Path(join(dirname(realpath(__file__)).replace('Header_Files', 'Webdriver'), _))
    temp_file.chmod(temp_file.stat().st_mode | stat.S_IEXEC)

# Delete_Unused_Functions
del Argument_Parser, catch_warnings, chmod, Path, redirect_stdout, simplefilter, stat, temp_file

# Static_Date
Date = strftime('%Y-%m-%d_%H-%M-%S')
