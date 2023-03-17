#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from .Variables import *
from ..Standard_Operations.Logs import *
from ..Workfiles.Scan_Cookie import Check_Security_Flags
from ..Workfiles.Scan_Certificate import Check_Certificate
from ..Workfiles.Scan_FTP import Check_FTP
from ..Workfiles.Scan_Fuzzing import Check_Site_Paths
from ..Workfiles.Scan_Header import Check_Site_Header
from ..Workfiles.Scan_Host_Name import Get_Host_Name
from ..Workfiles.Scan_HTTP_Methods import Check_HTTP_Methods
from ..Workfiles.Scan_Screen import Take_Screenshot
from ..Workfiles.Scan_SMTP import Check_SMTP

# Functions
def Thread_Scanning_Start(url, t_seconds, queue, dict_switch, screen_dir, switch_internet_connection, screenshot_wait, webdriver_timeout, ssl_timeout, dict_proxies, dict_auth, Host_Name = ""):
    try:
        Dict_Result = queue.get()

        # Socket_Timeout
        setdefaulttimeout(t_seconds)

        # Get_Host_Name
        Trace_File(f"{url} --> Host_Name", url, Host_Name)
        Host_Name = Get_Host_Name(url)
        Trace_File(f"{url} <-- Host_Name - OK", url, Host_Name)

        # Certificates
        if (dict_switch['scan_certificate'] != False and ('https://' in url or 'ssl://' in url)):
            Trace_File(f"{url} --> Certificate", url, Host_Name)
            Dict_Result['Certificate'][url] = Check_Certificate(url, t_seconds, Host_Name)
            Trace_File(f"{url} <-- Certificate - OK", url, Host_Name)

        # Fuzzing
        if (dict_switch['scan_fuzzing'] != False and '//' in url and 'http' in url):
            Dict_Result['Fuzzing'][url] = Check_Site_Paths(url, t_seconds)

        # Header
        if (dict_switch['scan_header'] != False and '//' in url and 'http' in url):
            Trace_File(f"{url} --> Header", url, Host_Name)
            Dict_Result['Header'][url], Dict_Result['Information'][url] = Check_Site_Header(url, t_seconds, Host_Name, dict_proxies, dict_auth)
            Trace_File(f"{url} <-- Header - OK", url, Host_Name)

        # HTTP_Methods
        if (dict_switch['scan_http_methods'] != False and '//' in url and 'http' in url):
            Trace_File(f"{url} --> HTTP-Methods", url, Host_Name)
            Dict_Result['HTTP_Methods'][url] = Check_HTTP_Methods(url, Host_Name, dict_proxies, dict_auth)
            Trace_File(f"{url} <-- HTTP-Methods - OK", url, Host_Name)

        # Recursive_Fuzzing_And_Screenshot
        if (dict_switch['scan_screenshot_recursive'] != False and '//' in url and 'http' in url):
            pass

        # Screenshot
        if (dict_switch['scan_screenshot'] != None and '//' in url and 'http' in url):
            Trace_File(f"{url} --> Screenshot", url, Host_Name)
            Take_Screenshot(url, dict_switch['scan_screenshot'], screen_dir, switch_internet_connection, screenshot_wait, webdriver_timeout)
            Trace_File(f"{url} <-- Screenshot - OK", url, Host_Name)

        # Security_Flags
        if (dict_switch['scan_security_flags'] != False and '//' in url and 'http' in url):
            Dict_Result['Security_Flag'][url] = Check_Security_Flags(url, t_seconds, Host_Name, dict_proxies, dict_auth)

        # SMTP
        if (dict_switch['scan_smtp'] != False and 'smtp://' in url):
            pass
            #Dict_Result['SMTP'][url] = Check_SMTP.(url, t_seconds, Host_Name)

        # SSH
        if (dict_switch['scan_ssh'] != False and 'ssh://' in url):
            try: Dict_Result['SSH'][url] = SSH_Vulns(url)
            except SSHException: Logs.Write_Log(url, Host_Name)

    except (ConnectionError, gaierror, WebDriverException, RequestException):
        Logs.Write_Log(url, Host_Name)
    finally:
        queue.put(Dict_Result)
