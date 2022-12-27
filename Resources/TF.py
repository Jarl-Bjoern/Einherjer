#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from Resources.VF import *

# Functions
def Thread_Scanning_Start(url, t_seconds, queue, driver_options, scan_ssl, scan_header, scan_fuzzing, scan_ssh, scan_fuzzing_recurse, scan_security_flag, Host_Name = "", Target = ""):
    try:
        Dict_Result = queue.get()
        Host_Name = Get_Host_Name(url)
        if (driver_options != None and '//' in url and 'http' in url):
            Take_Screenshot(url, driver_options)
        if (scan_header != False and '//' in url and 'http' in url):
            Dict_Result['Header'][url], Dict_Result['Information'][url] = Check_Site_Header(url, t_seconds, Host_Name)
        if (scan_ssl != False and '//' in url and 'http' in url):
            Dict_Result['SSL'] = SSL_Vulns(url, t_seconds)
        if (scan_security_flag != False and '//' in url and 'http' in url):
            Dict_Result['Security_Flag'] = Check_Security_Flags(url, t_seconds)
        if (scan_fuzzing != False and '//' in url and 'http' in url):
            Dict_Result['Fuzzing'] = Check_Site_Paths(url, t_seconds)
        if (scan_fuzzing_recurse != False and '//' in url and 'http' in url):
            pass
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
