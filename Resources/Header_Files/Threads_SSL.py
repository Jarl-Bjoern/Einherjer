#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from .Variables import *
from ..Standard_Operations.Logs import *
from ..Workfiles.Scan_SSL import SSL_Vulns

# Functions
def Thread_SSL_Start(array_ssl, t_seconds, queue, dict_switch, ssl_timeout, dict_proxies, dict_auth):
    try:
        Dict_Result = queue.get()

        # SSL
        if (dict_switch['scan_ssl'] != False):
            #Dict_Result['SSL'][url] = 
            SSL_Vulns(array_ssl, ssl_timeout)

    except (ConnectionError, gaierror, RequestException):
        Logs.Write_Log(url)
    finally:
        queue.put(Dict_Result)
