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
        'Header':        {},
        'HTTP_Methods':  {},
        'Information':   {},
        'Security_Flag': {},
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

        # Format_Filtering
        if ("csv" in file_format):
            from ..Format.CSV import CSV_Table
            CSV_Table(Dict_Temp, Location)
        elif ("docx" in file_format):
            from ..Format.Word import Word_Table
            Word_Table(Dict_Temp, Location)
        elif ("html" in file_format):
            from ..Format.HTML import HTML_Table
            HTML_Table(Dict_Temp, Location)
        elif ("json" in file_format):
            from ..Format.JSON import JSON_Table
            JSON_Table(Dict_Temp, Location)
        elif ("md" in file_format):
            from ..Format.Markdown import Markdown_Table
            Markdown_Table(Dict_Temp, Location)
        elif ("pdf" in file_format):
            from ..Format.PDF import Create_PDF
            Word_Table(Dict_Temp, Location)
            if (osname == 'nt'): Create_PDF(Location)
            else: print("At this point it's not be possible to convert a docx file into a pdf under linux.\nPlease try it under windows.\n")
        elif ("tex" in file_format):
            from ..Format.LaTeX import Latex_Table
            Latex_Table(Dict_Temp, Location)
        elif ("xlsx" in file_format):
            from ..Format.Excel import Excel_Table
            Excel_Table(Dict_Temp, Location)
        elif ("xml" in file_format):
            from ..Format.XML import XML_Table
            #XML_Table(Dict_Temp, Location)
        elif ("yaml" in file_format):
            from ..Format.YAML import YAML_Table
            #YAML_Table(Dict_Temp, Location)

    except (ConnectionError, gaierror, RequestException):
        pass
#        Logs.Write_Log(url)
    finally:
        queue.put(Dict_Result)
