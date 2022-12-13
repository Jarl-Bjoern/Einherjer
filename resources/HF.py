#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer C. B. Herold
# Vers 0.1 30.05.2022
# Vers 0.2 06.06.2022
# Vers 0.3 09.06.2022
# Vers 0.4 13.06.2022
# Vers 0.5 02.08.2022
# Vers 0.6 23.08.2022
# Vers 0.7 20.09.2022

# Author
__author__ = "Rainer C. B. Herold"
__copyright__ = "Copyright 2022, Rainer C. B. Herold"
__credits__ = "Rainer C. B. Herold"
__license__ = ""
__version__ = "0.7"
__maintainer__ = "Rainer C. B. Herold"
__status__ = "Production"

# Base_Function
def Module_Error(Text):
    input(Text), exit()

# Libraries
try:
    from argparse import ArgumentParser, FileType, RawTextHelpFormatter, SUPPRESS
    from contextlib import redirect_stdout
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from multiprocessing import active_children, cpu_count, Process, Queue
    from numpy import array
    from os import listdir, makedirs, name as osname, remove, system, walk
    from os.path import dirname, exists, join, realpath
    from requests import get
    from requests.exceptions import *
    from re import search
    from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TimeElapsedColumn, TimeRemainingColumn
    from selenium import webdriver
    from selenium.common.exceptions import *
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.chrome.service import Service
    ######
    from selenium.webdriver.remote.webdriver import WebDriver
    ######
    from socket import create_connection, gaierror, gethostbyaddr, herror, setdefaulttimeout
    from ssl import create_default_context, _create_unverified_context as create_unverified_context, get_server_certificate
    from subprocess import getoutput
    from sys import stdout
    from time import sleep, strftime, perf_counter
    from threading import Thread, enumerate as Th_enumerate
    from urllib3 import disable_warnings
    from urllib3.exceptions import *
    import asyncio, asyncssh, paramiko
    with redirect_stdout(None):
        from webdriver_manager.chrome import ChromeDriverManager
except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")
