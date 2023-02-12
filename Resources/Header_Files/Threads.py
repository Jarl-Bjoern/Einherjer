#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from .Variables import *
from ..Standard_Operations.Logs import *
from ..Workfiles.Scan_Cookie import Check_Security_Flags
from ..Workfiles.Scan_Certificate import Check_Certificate
from ..Workfiles.Scan_Header import Check_Site_Header
from ..Workfiles.Scan_Screen import Take_Screenshot

# Functions
def Thread_Scanning_Start(url, t_seconds, queue, dict_switch, screen_dir, switch_internet_connection, screenshot_wait, webdriver_timeout, Host_Name = "", Target = ""):
    try:
        Dict_Result = queue.get()
        Host_Name = Get_Host_Name(url)
        if (dict_switch['scan_screenshot'] != None and '//' in url and 'http' in url):
            Take_Screenshot(url, dict_switch['scan_screenshot'], screen_dir, switch_internet_connection, screenshot_wait, webdriver_timeout)
        if (dict_switch['scan_header'] != False and '//' in url and 'http' in url):
            Dict_Result['Header'][html_decode(url)], Dict_Result['Information'][html_decode(url)] = Check_Site_Header(url, t_seconds, Host_Name)
        if (dict_switch['scan_ssl'] != False and '//' in url and 'https' in url):
            Dict_Result['SSL'][html_decode(url)] = SSL_Vulns(url, t_seconds)
        if (dict_switch['scan_security_flags'] != False and '//' in url and 'http' in url):
            Dict_Result['Security_Flag'][html_decode(url)] = Check_Security_Flags(url, t_seconds, Host_Name)
        if (dict_switch['scan_certificate'] != False and '//' in url and 'https' in url):
            Dict_Result['Certificate'][html_decode(url)] = Check_Certificate(url, t_seconds, Host_Name)
        if (dict_switch['scan_fuzzing'] != False and '//' in url and 'http' in url):
            Dict_Result['Fuzzing'][html_decode(url)] = Check_Site_Paths(url, t_seconds)
#        if (scan_fuzzing_recurse != False and '//' in url and 'http' in url):
#            pass
        if (dict_switch['scan_ssh'] != False and '//' in url and 'ssh' in url):
            try:
                if (':' not in url): Dict_Result['SSH'][html_decode(url)] = SSH_Vulns((url, 22))
                else:
                    Target = url.split(':')
                    Dict_Result['SSH'][html_decode(url)] = SSH_Vulns((Target[0]), int(Target[1]))
            except SSHException: Logs.Write_Log(html_decode(url), Host_Name)
    except (ConnectionError, gaierror, WebDriverException, RequestException): Logs.Write_Log(html_decode(url), Host_Name)
    finally:
        queue.put(Dict_Result)
