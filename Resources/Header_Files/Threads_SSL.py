#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from .Variables import *
from ..Standard_Operations.Logs import *
from ..Workfiles.Scan_SSL import SSL_Vulns

# Functions
def Thread_SSL_Start(array_ssl, t_seconds, queue, dict_switch, ssl_timeout, dict_proxies, dict_auth, file_format, Location, language):
    Dict_Temp = {
        'Certificate':   {},
        'CORS':          {},
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

        # Global_Trace
        Port_Filter = ""
        def Global_Trace(timeout):
            Capture_Trace_File = sniff(filter="tcp", count=1000000, timeout=timeout)
            wrpcap(f'{Location}/einherjer_trace.pcap', Capture_Trace_File, append=True)

        t1 = Thread(target=Global_Trace, args=[t_seconds], daemon=True)
        t1.start()

        # SSL
        if (dict_switch['scan_ssl'] != False):
            # Trace_Start
#            for _ in array_ssl:
            Logs.Trace_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.ORANGE+f'{array_ssl}'+Colors.RED+' -> '+Colors.CYAN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+' - Scan_SSL - '+Colors.BLUE+'Trying to connect'+Colors.RESET,
                join(Location, 'Logs')
            )

            # Scan_SSL
            Dict_Temp['SSL'] = SSL_Vulns(array_ssl, ssl_timeout, Location)
            Dict_Result['SSL'].update(Dict_Temp['SSL'])

            # Trace_End
            Logs.Trace_File(
                Colors.ORANGE+f'{array_ssl}'+Colors.RED+' <- '+Colors.CYAN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+' - Scan_SSL - '+Colors.GREEN+'OK'+Colors.RESET,
                join(Location, 'Logs')
            )

        # Write_File_Format
        file_format(Dict_Temp, Location, language)

    except (ConnectionError, gaierror, RequestException):
        pass
#        Logs.Write_Log(url)
    finally:
        queue.put(Dict_Result, block=False, timeout=30)
