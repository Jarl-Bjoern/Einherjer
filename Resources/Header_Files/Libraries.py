#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Author
__author__     = "Rainer Christian Bjoern Herold"
__copyright__  = "Copyright 2022-2023, Rainer Christian Bjoern Herold"
__credits__    = "Rainer Christian Bjoern Herold"
__license__    = "MIT license"
__version__    = "0.8"
__maintainer__ = "Rainer Christian Bjoern Herold"
__status__     = "Production"

# Base_Function
def Module_Error(Text):
    try: input(Text), exit()
    except KeyboardInterrupt: exit()

# Define_Module_Path
from os.path import dirname, realpath
from sys import path as SYSTEM_PATH
SYSTEM_PATH.append(dirname(realpath(__file__)).split('Resources/Header_Files')[0])

# Libraries
try:
    from aiohttp.client_exceptions import *
    from base64              import b64encode
    from contextlib          import redirect_stdout
    from datetime            import datetime
    from http.client         import RemoteDisconnected
    from ipaddress           import IPv4Network
    from multiprocessing     import active_children, Process, Queue
    from numpy               import array
    from os                  import chmod, getcwd, listdir, makedirs, name as osname, remove, rmdir, system, walk
    from os.path             import exists, isdir, isfile, join
    from pathlib             import Path
    from pykeepass           import create_database
    from pyzipper            import AESZipFile, WZ_AES, ZIP_LZMA
    from requests.exceptions import *
    from re                  import findall, search, split as resplit
    from rich.progress       import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TimeElapsedColumn, TimeRemainingColumn
    from selenium.common.exceptions import *
    from socket              import gaierror, gethostbyaddr, gethostbyname, herror, setdefaulttimeout as socket_defaulttimeout
    from ssl                 import cert_time_to_seconds, create_default_context, _create_unverified_context as create_unverified_context, get_server_certificate, SSLError, SSLZeroReturnError
    from subprocess          import getoutput, run
    from stdiomask           import getpass
    from secrets             import SystemRandom
    from shutil              import rmtree
    from sys                 import argv, stdout
    from time                import sleep, strftime, time
    from threading           import Thread, enumerate as Th_enumerate
    from traceback           import print_exc
    from urllib3             import disable_warnings
    from urllib3.exceptions  import *
    from urllib.parse        import quote_plus as url_encode, unquote_plus as url_decode
    from warnings            import catch_warnings, simplefilter
    from xml.etree.ElementTree import ParseError
    from zipfile             import ZipFile
    import stat, xml.etree.ElementTree as ET
    with catch_warnings():
        simplefilter("ignore")
        from paramiko.ssh_exception import SSHException

    # Chromium_Check
    if (osname != 'nt'):
        if ('(none)' in getoutput('apt-cache policy chromium')):
            Module_Error(f"\n{getoutput('apt-cache policy chromium')}\n\nIt looks like that you do not have \033[0;31mChromium\033[0m installed.\n\nPlease use \033[1;33mapt install -y chromium\033[0m.\n\n")
        if ('(none)' in getoutput('apt-cache policy chromium-driver')):
            Module_Error(f"\n{getoutput('apt-cache policy chromium-driver')}\n\nIt looks like that you do not have \033[0;31mChromium-Driver\033[0m installed.\n\nPlease use \033[1;33mapt install -y chromium-driver\033[0m.\n\n")

    # Argument_Parser
    try:
        Temp_Arg_List = argv

        if (argv[1] == "--filter-mode"):
            argv.remove('--filter-mode')
            from .ArgParser_Filter import Argument_Parser
            args, Program_Mode = Argument_Parser(), "Filter_Mode"

            if (args.screenshot_location != None):
                from cv2 import countNonZero, imread, imwrite, rectangle, split as cvsplit, subtract

            if (args.qrcode_picture_location != None):
                from PIL import Image
                from pyzbar import pyzbar

        elif (argv[1] == "--brute-force-mode"):
            argv.remove('--brute-force-mode')
            from .ArgParser_Brute import Argument_Parser
            args, Program_Mode = Argument_Parser(), "Brute_Force_Mode"

            # Brute_Force_Module_Filtering
            if (args.brute_all                    == False and
                args.brute_dns                    == False and
                args.brute_smtp                   == False and
                args.brute_fuzzing                == False and
                args.brute_snmp                   == False and
                args.brute_ftp                    == False and
                args.brute_screenshot_recursive   == False):
                        from .ArgParser_Scan_Intro import Argument_Parser
                        Argument_Parser("\n\n\t\t\t\t\tThe scanning method is missing!\n\t\t\t    For more information use the parameter -h or --help.\n"), exit()
            elif (args.brute_all                  != False and
                  args.brute_dns                  == False and
                  args.brute_smtp                 == False and
                  args.brute_fuzzing              == False and
                  args.brute_snmp                 == False and
                  args.brute_ftp                  == False and
                  args.brute_screenshot_recursive == False):
                        from aiohttp  import BasicAuth, ClientSession, TCPConnector
                        from cv2      import countNonZero, error as CVError, imread, imwrite, rectangle, split as cvsplit, subtract
                        from ftplib   import error_perm, FTP
                        from json     import loads as json_loads
                        from os       import environ, rename
                        from requests import get, request, Session
                        from requests.adapters import HTTPAdapter
                        from requests_pkcs12 import get as pkcs_get, Pkcs12Adapter
                        from selenium import webdriver
                        from selenium.webdriver.common.by        import By
                        from selenium.webdriver.common.keys      import Keys
                        from selenium.webdriver.chrome.options   import Options
                        from selenium.webdriver.chrome.service   import Service
                        from selenium.webdriver.remote.webdriver import WebDriver
                        from webbrowser import open as webbrowser_open
                        import asyncio, pysnmp
                        with redirect_stdout(None):
                            from webdriver_manager.chrome import ChromeDriverManager
            elif (args.brute_all == False):
                if (args.brute_fuzzing != False):
                    from aiohttp  import BasicAuth, ClientSession, TCPConnector
                    import asyncio
                if (args.brute_screenshot_recursive != False):
                    from cv2      import countNonZero, error as CVError, imread, imwrite, rectangle, split as cvsplit, subtract
                    from os       import environ, rename
                    from selenium import webdriver
                    from selenium.webdriver.common.by        import By
                    from selenium.webdriver.common.keys      import Keys
                    from selenium.webdriver.chrome.options   import Options
                    from selenium.webdriver.chrome.service   import Service
                    from selenium.webdriver.remote.webdriver import WebDriver
                    from webbrowser import open as webbrowser_open
                    with redirect_stdout(None):
                       from webdriver_manager.chrome import ChromeDriverManager
                if (args.brute_fuzzing != False or args.brute_dns != False):
                    from requests        import get
                    from requests_pkcs12 import get as pkcs_get, Pkcs12Adapter

        elif (argv[1] == "--scanning-mode"):
            argv.remove('--scanning-mode')
            from .ArgParser_Scan import Argument_Parser
            args, Program_Mode = Argument_Parser(), "Scanning_Mode"

            # Scanning_Module_Filtering
            if (args.scan_all                 == False and
                args.scan_site_certificate    == False and
                args.scan_dns                 == False and
                args.scan_ftp                 == False and
                args.scan_host_name           == False and
                args.scan_site_http_methods   == False and
                args.scan_site_screenshot     == False and
                args.scan_site_ssl            == False and
                args.scan_site_header         == False and
                args.scan_smtp                == False and
                args.scan_ssh                 == False and
                args.scan_security_flags      == False):
                        from .ArgParser_Scan_Intro import Argument_Parser
                        Argument_Parser("\n\n\t\t\t\t\tThe scanning method is missing!\n\t\t\t    For more information use the parameter -h or --help.\n"), exit()
            elif (args.scan_all               != False and
                  args.scan_site_certificate  == False and
                  args.scan_dns               == False and
                  args.scan_ftp               == False and
                  args.scan_host_name         == False and
                  args.scan_site_http_methods == False and
                  args.scan_site_screenshot   == False and
                  args.scan_site_ssl          == False and
                  args.scan_site_header       == False and
                  args.scan_smtp              == False and
                  args.scan_ssh               == False and
                  args.scan_security_flags    == False):
                        from aiohttp                      import BasicAuth, ClientSession, TCPConnector
                        from asyncssh                     import Error as AsyncSSHError, get_server_auth_methods, SSHClient, SSHClientConnection
                        from cryptography.x509            import load_der_x509_certificate
                        from cryptography.hazmat.backends import default_backend
                        from cryptography.exceptions                         import InvalidSignature, UnsupportedAlgorithm
                        from cryptography.hazmat.primitives                  import hashes, serialization
                        from cryptography.hazmat.primitives.asymmetric       import ec, rsa, padding
                        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
                        from cryptography.hazmat.primitives.ciphers          import algorithms, Cipher, modes
                        from cv2       import countNonZero, error as CVError, imread, imwrite, rectangle, split as cvsplit, subtract
                        from dns.query import xfr
                        from dns.zone  import from_xfr
                        from ftplib    import error_perm, FTP
                        from hashlib   import md5, sha1, sha256, sha512
                        from json      import loads as json_loads
                        from os        import environ, rename
                        from pysnmp.hlapi import *
                        from requests  import get, request, Session
                        from requests_pkcs12   import get as pkcs_get, Pkcs12Adapter
                        from requests.adapters import HTTPAdapter
                        from selenium  import webdriver
                        from selenium.webdriver.common.by        import By
                        from selenium.webdriver.common.keys      import Keys
                        from selenium.webdriver.chrome.options   import Options
                        from selenium.webdriver.chrome.service   import Service
                        from selenium.webdriver.remote.webdriver import WebDriver
                        from smtplib import SMTP, SMTPServerDisconnected
                        from sslyze  import (
                            Scanner,
                            ServerNetworkLocation,
                            ServerNetworkConfiguration,
                            ServerScanRequest,
                            ServerScanResultAsJson,
                            ServerHostnameCouldNotBeResolved,
                            SslyzeOutputAsJson,
                            ServerScanStatusEnum
                        )
                        from socket     import AF_INET, create_connection, socket, SOCK_STREAM
                        from subprocess import Popen
                        from webbrowser import open as webbrowser_open
                        import asyncio
                        with catch_warnings():
                            simplefilter("ignore")
                            from paramiko.transport       import Transport
                        with redirect_stdout(None):
                            from webdriver_manager.chrome import ChromeDriverManager
            elif (args.scan_all == False):
                if (args.scan_dns != False):
                    from dns.query       import xfr
                    from dns.zone        import from_xfr
                if (args.scan_ftp != False):
                    from ftplib          import error_perm, FTP
                if (args.scan_security_flags != False):
                    from requests        import Session
                    from requests_pkcs12 import get as pkcs_get, Pkcs12Adapter
                    from requests.adapters import HTTPAdapter
                if (args.scan_smtp != False):
                    from smtplib import SMTP, SMTPServerDisconnected
                if (args.scan_snmp != False):
                    from pysnmp.hlapi import *
                if (args.scan_site_header != False):
                    from requests        import get
                    from requests_pkcs12 import get as pkcs_get, Pkcs12Adapter
                    from requests.adapters import HTTPAdapter
                if (args.scan_site_http_methods != False):
                    from aiohttp import BasicAuth, ClientSession, TCPConnector
                    import asyncio
                if (args.scan_site_screenshot != False):
                        from cv2      import countNonZero, error as CVError, imread, imwrite, rectangle, split as cvsplit, subtract
                        from os       import environ, rename
                        from selenium import webdriver
                        from selenium.webdriver.common.by        import By
                        from selenium.webdriver.common.keys      import Keys
                        from selenium.webdriver.chrome.options   import Options
                        from selenium.webdriver.chrome.service   import Service
                        from selenium.webdriver.remote.webdriver import WebDriver
                        from webbrowser import open as webbrowser_open
                        with redirect_stdout(None):
                           from webdriver_manager.chrome import ChromeDriverManager
                if (args.scan_ssh != False):
                    from asyncssh   import Error as AsyncSSHError, get_server_auth_methods, SSHClient, SSHClientConnection
                    from cryptography.exceptions                         import InvalidSignature, UnsupportedAlgorithm
                    from cryptography.hazmat.primitives                  import hashes, serialization
                    from cryptography.hazmat.primitives.asymmetric       import ec, rsa, padding
                    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
                    from cryptography.hazmat.primitives.ciphers          import algorithms, Cipher, modes
                    from hashlib    import md5, sha1, sha256, sha512
                    from subprocess import Popen
                    import asyncio
                    with catch_warnings():
                        simplefilter("ignore")
                        from paramiko.transport import Transport
                if (args.scan_site_ssl != False or args.scan_site_certificate != False):
                    from cryptography.x509 import load_der_x509_certificate
                    from cryptography.hazmat.backends import default_backend
                    from json   import loads as json_loads
                    from socket import create_connection
                    from sslyze import (
                        Scanner,
                        ServerNetworkLocation,
                        ServerScanStatusEnum,
                        ServerNetworkConfiguration,
                        ServerScanRequest,
                        ServerScanResultAsJson,
                        ServerHostnameCouldNotBeResolved,
                        SslyzeOutputAsJson
                    )
        elif (argv[1] == '-h'):
            from .ArgParser_Mode import Argument_Parser
            Argument_Parser(""), exit()
        else:
            from .ArgParser_Mode import Argument_Parser
            Argument_Parser("\n\n\t\t\t   The program cannot be started without using the mode of the program!\n\t\t\tFor more information use one of the modes with the parameter -h or --help.\n"), exit()

        if (Program_Mode == 'Brute_Force_Mode' or
            Program_Mode == 'Scanning_Mode'):
                # Format_Import
                if ("csv" in args.format):
                    import csv
                elif ("docx" in args.format):
                    from docx             import Document
                    from docx.enum.style  import WD_STYLE_TYPE
                    from docx.enum.table  import WD_ALIGN_VERTICAL
                    from docx.enum.text   import WD_ALIGN_PARAGRAPH
                    from docx.oxml.shared import OxmlElement
                    from docx.oxml.ns     import qn
                    from docx.shared      import Inches, Pt, RGBColor
                elif ("json" in args.format):
                    import json
                elif ("pdf" in args.format):
                    if (osname == 'nt'):
                        from docx2pdf     import convert
                    else:
                        print("At this point it's not be possible to convert a docx file into a pdf under linux.\nPlease try it under windows.\n")
                elif ("xlsx" in args.format):
                    from xlsxwriter       import Workbook
                    from pandas           import ExcelFile, DataFrame, read_excel

        try:
            del Argument_Parser, argv
        except NameError:
            pass
    except IndexError:
        from .ArgParser_Mode import Argument_Parser
        Argument_Parser("\n\n\t\t\t   The program cannot be started without using the mode of the program!\n\t\t\tFor more information use one of the modes with the parameter -h or --help.\n"), exit()
except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")

# Change_Permissions_For_Webdriver
try:
    for _ in listdir(dirname(realpath(__file__)).replace('Header_Files', 'Webdriver')):
        temp_file = Path(join(dirname(realpath(__file__)).replace('Header_Files', 'Webdriver'), _))
        temp_file.chmod(temp_file.stat().st_mode | stat.S_IEXEC)
    del temp_file
except FileNotFoundError: pass

# Delete_Unused_Functions
del catch_warnings, chmod, Path, redirect_stdout, simplefilter, stat

# Static_Date
Date = strftime('%Y-%m-%d_%H-%M-%S')
