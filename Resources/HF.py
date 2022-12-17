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
__copyright__ = "Copyright 2022, Rainer Christian Bjoern Herold"
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
    from argparse import ArgumentParser, FileType, RawTextHelpFormatter, SUPPRESS
    from contextlib import redirect_stdout
    from datetime import datetime
    from multiprocessing import active_children, cpu_count, Process, Queue
    from numpy import array
    from os import getcwd, listdir, makedirs, name as osname, remove, system, walk
    from os.path import dirname, exists, join, realpath
    from requests import get, Session
    from requests.exceptions import *
    from random import shuffle
    from re import search, split as resplit
    from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TimeElapsedColumn, TimeRemainingColumn
    from selenium.common.exceptions import *
    from socket import create_connection, gaierror, gethostbyaddr, gethostbyname, herror, setdefaulttimeout
    from ssl import cert_time_to_seconds, create_default_context, _create_unverified_context as create_unverified_context, get_server_certificate
    from subprocess import getoutput
    from sys import stdout
    from time import sleep, strftime, time
    from threading import Thread, enumerate as Th_enumerate
    from traceback import print_exc
    from urllib3 import disable_warnings
    from urllib3.exceptions import *
except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")
