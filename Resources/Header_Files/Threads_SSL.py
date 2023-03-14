#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from .Variables import *
from ..Standard_Operations.Logs import *
from ..Workfiles.Scan_SSL import SSL_Vulns

# Functions
def Thread_Scanning_Start(array_ssl, t_seconds, queue, dict_switch, ssl_timeout, dict_proxies, dict_auth, Target = ""):
    try:
        Dict_Result = queue.get()

        # SSL
        if (dict_switch['scan_ssl'] != False):
            Dict_Result['SSL'][url] = SSL_Vulns(array_ssl, ssl_timeout, Host_Name)

    except (ConnectionError, gaierror, WebDriverException, RequestException):
        Logs.Write_Log(url, Host_Name)
    finally:
        queue.put(Dict_Result)
