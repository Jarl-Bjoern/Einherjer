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

        # Socket_Timeout
        setdefaulttimeout(t_seconds)

        # SSL
        if (dict_switch['scan_ssl'] != False):
            # Trace_Start
            Logs.Trace_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.ORANGE+f'{url}'+Colors.RED+' -> '+Colors.RESET+'Host_Name - '+Colors.BLUE+'Trying to connect'+Colors.RESET,
                join(Location, 'Logs')
            )

            # Scan_SSL
            Dict_Result['SSL'].update(SSL_Vulns(array_ssl, ssl_timeout))

            # Trace_End
            Logs.Trace_File(
                Colors.ORANGE+f'{url}'+Colors.RED+' <- '+Colors.RESET+'Host_Name - '+Colors.GREEN+'OK'+Colors.RESET,
                join(Location, 'Logs')
            )

    except (ConnectionError, gaierror, RequestException):
        pass
#        Logs.Write_Log(url)
    finally:
        queue.put(Dict_Result)
