#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from Resources.VF import *

# Functions
def Thread_Scanning_Start(url, t_seconds, queue, driver_options, scan_ssl, scan_header, scan_fuzzing, scan_ssh, scan_fuzzing_recurse, scan_security_flag, Count_Double_Point = 0, Host_Name = "", Target = ""):
    try:
        Dict_Result = queue.get()
        if (driver_options != None and '//' in url and 'http' in url): Take_Screenshot(url, driver_options)
        if (scan_header != False and '//' in url and 'http' in url):
            Dict_Temp_Header, Dict_Temp_Information_Disclosure = {},{}
            try:
                r = get(url, timeout=(t_seconds, t_seconds), verify=False, allow_redirects=True)
                # Host_Name_Filtering
                Host_Name = Get_Host_Name(url)
                if (Host_Name != ""):
                    Dict_Temp_Header['DNS'], Dict_Temp_Information_Disclosure['DNS'] = Host_Name, Host_Name
                else: Dict_Temp_Header['DNS'], Dict_Temp_Information_Disclosure['DNS'] = "",""
                # Header_Check
                for Header in r.headers.items():
                    if (Header[0].upper() in Array_Header): Dict_Temp_Header[Header[0].upper()] = Header[1].upper()
                    elif (Header[0].upper() in Array_Information_Disclosure_Header): Dict_Temp_Information_Disclosure[Header[0].upper()] = Header[1].upper()
                    else:
                        for Temp_Header in array(Array_Header):
                            if (Temp_Header not in Dict_Temp_Header): Dict_Temp_Header[Temp_Header] = "FEHLT"
                    Dict_Result['Header'][url] = Dict_Temp_Header
                    if (len(Dict_Temp_Information_Disclosure) > 0): Dict_Result['Information'][url] = Dict_Temp_Information_Disclosure
                if (Host_Name != ""): Logs.Log_File(Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - {Host_Name} - '+Colors.BLUE+f'{r}'+Colors.ORANGE+'\nOriginal Output'+Colors.RED+' -> '+Colors.RESET+f'{r.headers.items()}'+Colors.ORANGE+'\n Einherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp_Header}\n')
                else: Logs.Log_File(Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - '+Colors.BLUE+f'{r}'+Colors.ORANGE+'\nOriginal Output'+Colors.RED+' -> '+Colors.RESET+f'{r.headers.items()}'+Colors.ORANGE+'\n Einherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp_Header}\n')
            except ReadTimeout: Logs.Write_Log(url, Host_Name)
        if (scan_ssl != False and '//' in url and 'http' in url): Dict_Result['SSL'] = SSL_Vulns(url, t_seconds)
        if (scan_security_flag != False and '//' in url and 'http' in url): Dict_Result['Security_Flag'] = Check_Security_Flags(url, t_seconds)
        if (scan_fuzzing != False and '//' in url and 'http' in url): Dict_Result['Fuzzing'] = Check_Site_Paths(url, t_seconds)
        if (scan_fuzzing_recurse != False and '//' in url and 'http' in url): pass
        if (scan_ssh != False and '//' not in url):
            try:
                if (':' not in url): Dict_Result['SSH'][url] = SSH_Vulns((url, 22))
                else:
                    Target = url.split(':')
                    Dict_Result['SSH'][url] = SSH_Vulns((Target[0]), int(Target[1]))
            except paramiko.ssh_exception.SSHException: Logs.Write_Log(url, Host_Name)
    except (ConnectionError, gaierror, WebDriverException, RequestException): Logs.Write_Log(url, Host_Name)
    finally:
        queue.put(Dict_Result)
