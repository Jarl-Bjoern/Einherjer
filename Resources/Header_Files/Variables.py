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
    # Templates
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

    if (args.read_custom_header_file != False):
        Dict_Custom_Header = Standard.Read_JSON_File(dirname(realpath(__file__)).replace('Resources/Header_Files', "Config/http_custom_header.json"))
    else:
        Dict_Custom_Header = Standard.Read_JSON_File(dirname(realpath(__file__)).replace('Resources/Header_Files', "Config/http_custom_header.json"))

    Array_Security_Flags                = Standard.Read_YAML_Config_File(dirname(realpath(__file__)).replace('Resources/Header_Files', 'Config/http_config.yaml'), 'cookie_flags')
    Array_Deprecated_Header             = Standard.Read_YAML_Config_File(dirname(realpath(__file__)).replace('Resources/Header_Files', 'Config/http_config.yaml'), 'http_deprecated_header')
    Array_CORS_Header                   = Standard.Read_YAML_Config_File(dirname(realpath(__file__)).replace('Resources/Header_Files', 'Config/http_config.yaml'), 'http_cors_header')
    Array_Information_Disclosure_Header = Standard.Read_YAML_Config_File(dirname(realpath(__file__)).replace('Resources/Header_Files', 'Config/http_config.yaml'), 'http_information_disclosure_header')
    Array_HTTP_Methods                  = Standard.Read_YAML_Config_File(dirname(realpath(__file__)).replace('Resources/Header_Files', 'Config/http_config.yaml'), 'http_methods')
    Array_TLS_Algorithms                = Standard.Read_Template(dirname(realpath(__file__)).replace('Resources/Header_Files', "Config/ssl_ciphers.txt"))

    # Arrays
    Array_Paths, Array_SSL_Vulns, Array_Results = [],[],[]
    Array_SSH_Header = ['encryption_algorithms', 'kex_algorithms', 'mac_algorithms', 'server_host_key_algorithms']

    # Variables
    COLOR_Headline       = "black"

if (Program_Mode == "Scanning_Mode" or Program_Mode == "Filter_Mode"):
    Array_SSH_Algorithms = Standard.Read_YAML_Template(dirname(realpath(__file__)).replace('Resources/Header_Files', "Config/ssh_ciphers.yaml"))
    Screenshot_Color     = Standard.Read_Color(dirname(realpath(__file__)).replace('Resources/Header_Files', "Config/http_screenshot_color.cfg"))

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

Dict_Protocols = {
    "test": {}
}

Dict_Timer_Presets = {
    "1": {}
}

Dict_State = {
    "State": [],
    "Location": dirname(realpath(__file__)).split('Resources/Header_Files')[0]
}
