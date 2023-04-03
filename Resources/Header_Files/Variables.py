#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from .Libraries import *
from ..Standard_Operations.Colors import Colors
from ..Standard_Operations.Standard import *
from ..Standard_Operations.Logs import *

# Template_Filtering
if (Program_Mode == "Scanning_Mode"):
    Array_Security_Flags = Standard.Read_Template(dirname(realpath(__file__)).replace('Resources/Header_Files', "Templates/http_cookie_security.txt"))
    if (args.read_config_http_header       == True and
        args.read_config_http_header_api   == False):
            Dict_Header = Standard.Read_File_Special(dirname(realpath(__file__)).replace('Resources/Header_Files', "Templates/http_header.txt"))
    elif (args.read_config_http_header     == False and
          args.read_config_http_header_api == True):
            Dict_Header = Standard.Read_File_Special(dirname(realpath(__file__)).replace('Resources/Header_Files', "Templates/http_header_api.txt"))
    elif (args.read_config_http_header     == True and
          args.read_config_http_header_api == True):
            exit(Colors.RED+"It's not possible to use both http_header templates at the same time."+Colors.RESET)
    else:   Dict_Header = {}

    Array_Information_Disclosure_Header = Standard.Read_Template(dirname(realpath(__file__)).replace('Resources/Header_Files', "Templates/http_information_disclosure.txt"))
    Array_HTTP_Methods                  = Standard.Read_Template(dirname(realpath(__file__)).replace('Resources/Header_Files', "Templates/http_methods.txt"))
    Array_TLS_Algorithms                = Standard.Read_Template(dirname(realpath(__file__)).replace('Resources/Header_Files', "Templates/ssl_ciphers.txt"))

    # Arrays
    Array_Paths, Array_SSL_Vulns, Array_Results = [],[],[]
    Array_SSH_Header = ['kex_algorithms', 'server_host_key_algorithms', 'encryption_algorithms', 'mac_algorithms']

    # Variables
    COLOR_Headline       = "black"
    existing_nmap_file   = ""
    Chromedriver_Version = "110.0.5481.77"

if (Program_Mode == "Scanning_Mode" or Program_Mode == "Filter_Mode"):
    Array_SSH_Algorithms = Standard.Read_Template(dirname(realpath(__file__)).replace('Resources/Header_Files', "Templates/ssh_ciphers.txt"))

# Design
disable_warnings(InsecureRequestWarning)
progress_columns = (
    SpinnerColumn(),
    "[progress.description]{task.description}",
    BarColumn(),
    TaskProgressColumn(),
    "Elapsed:",
    TimeElapsedColumn(),
    "Remaining:",
    TimeRemainingColumn(),
)

# Dictionaries
Dict_Ports = {
    "TCP": {},
    "UDP": {}
}

# Functions
def Check_Website(url, t_seconds, Dict_Temp = {}, Array_Output = [], Temp_Array = []):
    Array_Filter = ["Apache/", "Tomcat/", "Server Version:"]

    with open('/opt/test.txt', 'w') as f:
         for i in array(Read_File(argv[1])):
             r = get(str(i), verify=False, timeout=(25,25))
             for _ in array(Array_Filter):
                 x = search(rf'^.*{_}.*', str(r.content))
                 if (x != None):
                    for j in array(r.text.splitlines()):
                        if (_ in j):
                            Temp_Array = resplit("<dl>|<dt>|</dt>", j)
                            if (len(Temp_Array) > 1):
                                for k in array(Temp_Array):
                                    if (len(k) > 1):
                                        if (f'{i} - {k}' not in Array_Output): Array_Output.append(f'{i} - {k}')

    return Dict_Temp
