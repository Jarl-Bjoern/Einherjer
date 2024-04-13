#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from .Variables import *
from ..Standard_Operations.Logs import *

# Functions
def Thread_SSL_Start(array_ssl, t_seconds, queue, dict_switch, ssl_timeout, dict_proxies, dict_auth, file_format, Location):
    Dict_Temp = {
        'Fuzzing':       {},
    }

    try:
        Dict_Result = queue.get()

        # Socket_Timeout
        socket_defaulttimeout(t_seconds)

        # Fuzzing
        if (dict_switch['scan_fuzzing'] != False and '//' in url and 'http' in url):
            # Library_Import
            from ..Workfiles.Fuzz_Fuzzing import Check_Site_Paths

            # Trace_Start
            Logs.Trace_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.ORANGE+f'{array_ssl}'+Colors.RED+' -> '+Colors.RESET+'Scan_SSL - '+Colors.BLUE+'Trying to connect'+Colors.RESET,
                join(Location, 'Logs')
            )

            # Brute_Fuzzing
            Dict_Temp['Fuzzing'][url] = Check_Site_Paths(url, t_seconds)
            Dict_Result['Fuzzing'].update(Dict_Temp['Fuzzing'])

            # Trace_End
            Logs.Trace_File(
                Colors.ORANGE+f'{array_ssl}'+Colors.RED+' <- '+Colors.RESET+'Scan_SSL - '+Colors.GREEN+'OK'+Colors.RESET,
                join(Location, 'Logs')
            )


        # Recursive_Fuzzing_And_Screenshot
        if (dict_switch['scan_screenshot_recursive'] != False and '//' in url and 'http' in url):
            pass


        # Write_File_Format
        file_format(Dict_Temp, Location)

    except (ConnectionError, gaierror, RequestException):
        pass
#        Logs.Write_Log(url)
    finally:
        queue.put(Dict_Result)
