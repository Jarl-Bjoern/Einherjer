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
        'SNMP':          {},
        'SSH':           {},
        'SSL':           {}
    }

    try:
        Dict_Result = queue.get()

        # Socket_Timeout
        socket_defaulttimeout(t_seconds)

        # SSL
        if (dict_switch['scan_ssl'] != False):
            Port_Protocol_Filter, Array_Filtered_Ports = "tcp and ", []

            # Port_Filter
            for _ in array_ssl:
                if   ('ssl://' in _):   Check_Host = _.split('ssl://')[1]
                elif ('https://' in _): Check_Host = _.split('https://')[1]

                try:
                    IPv4Network(Check_Host)
                    IP_Check = True
                except:
                    IP_Check = False

                if (IP_Check == True):
                    if   (_.count(':') == 2): Temp_Port = _[::-1].split(':')[0][::-1]
                    elif (_.count(':') == 1): Temp_Port = _[::-1].split(':')[0]
                    elif (_.count(':') == 0): Temp_Port = '443'
                else:
                    Temp_Port = '443'

                if (Temp_Port not in Array_Filtered_Ports): Array_Filtered_Ports.append(Temp_Port)

            for _ in range(0, len(Array_Filtered_Ports)):
                Port_Protocol_Filter += f"port {Array_Filtered_Ports[_]}  "
                if ((_ + 1) != len(Array_Filtered_Ports)):
                    Port_Protocol_Filter += f"and "

            # Start_Trace
            a = AsyncSniffer(filter=Port_Protocol_Filter)
            a.start()

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

            # Trace_Write
            Captured_Packages = a.stop()
            wrpcap(f'{Location}/Logs/einherjer_trace.pcap', Captured_Packages, append=True)

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
