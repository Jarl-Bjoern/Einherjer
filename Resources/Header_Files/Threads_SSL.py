#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from .Variables import *
from ..Standard_Operations.Logs import *
from ..Workfiles.Scan_SSL import SSL_Vulns

# Functions
def Thread_SSL_Start(array_ssl, t_seconds, queue, dict_switch, ssl_timeout, dict_proxies, dict_auth, file_format, Location):
    Dict_Temp = {
        'Certificate':   {},
        'DNS':           {},
        'FTP':           {},
        'Header':        {},
        'HTTP_Methods':  {},
        'Information':   {},
        'Security_Flag': {},
        'SMTP':          {},
        'SSH':           {},
        'SSL':           {}
    }

    try:
        Dict_Result = queue.get()

        # Socket_Timeout
        socket_defaulttimeout(t_seconds)

        # SSL
        if (dict_switch['scan_ssl'] != False):
            # Trace_Start
            Logs.Trace_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.ORANGE+f'{array_ssl}'+Colors.RED+' -> '+Colors.RESET+'Scan_SSL - '+Colors.BLUE+'Trying to connect'+Colors.RESET,
                join(Location, 'Logs')
            )

            # Scan_SSL
            Dict_Temp['SSL'] = SSL_Vulns(array_ssl, ssl_timeout, Location)
            Dict_Result['SSL'].update(Dict_Temp['SSL'])

            # Trace_End
            Logs.Trace_File(
                Colors.ORANGE+f'{array_ssl}'+Colors.RED+' <- '+Colors.RESET+'Scan_SSL - '+Colors.GREEN+'OK'+Colors.RESET,
                join(Location, 'Logs')
            )

        # Write_File_Format
        file_format(Dict_Temp, Location)

    except (ConnectionError, gaierror, RequestException):
        pass
#        Logs.Write_Log(url)
    finally:
        queue.put(Dict_Result)
