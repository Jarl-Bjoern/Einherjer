#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from .Variables import *
from ..Standard_Operations.Logs import *
from ..Standard_Operations.Colors import Colors
from ..Standard_Operations.Standard import Standard
from ..Workfiles.Scan_FTP import Check_FTP
from ..Workfiles.Scan_SMTP import Check_SMTP

# Functions
def Thread_Scanning_Start(url, t_seconds, queue, dict_switch, screen_dir, switch_internet_connection, screenshot_wait, webdriver_timeout, ssl_timeout, dict_proxies, dict_auth, file_format, Location, allow_redirects, Host_Name = ""):
    Dict_Temp = {
        'Certificate': {},
        'Header': {},
        'HTTP_Methods': {},
        'Information': {},
        'Security_Flag': {},
        'SSH': {},
        'SSL': {}
    }

    try:
        Dict_Result = queue.get()

        # Socket_Timeout
        setdefaulttimeout(t_seconds)

        # Get_Host_Name
        if (dict_switch['scan_host_name'] != False):
            # Library_Import
            from ..Workfiles.Scan_Host_Name import Get_Host_Name

            # Trace_Start
            Logs.Trace_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.ORANGE+f'{url}'+Colors.RED+' -> '+Colors.RESET+'Host_Name - '+Colors.BLUE+'Trying to connect'+Colors.RESET,
                join(Location, 'Logs')
            )

            # Get_Host_Name
            Host_Name = Get_Host_Name(url)
            Standard.Write_Output_File('DNS_Template.txt', f'{url}:{Host_Name}', Location)

            # Trace_End
            Logs.Trace_File(
                Colors.ORANGE+f'{url}'+Colors.RED+' <- '+Colors.RESET+'Host_Name - '+Colors.GREEN+'OK'+Colors.RESET,
                join(Location, 'Logs')
            )


        # Certificates
        if (dict_switch['scan_certificate'] != False and ('https://' in url or 'ssl://' in url)):
            # Library_Import
            from ..Workfiles.Scan_Certificate import Check_Certificate

            # Trace_Start
            Logs.Trace_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.ORANGE+f'{url}'+Colors.RED+' -> '+Colors.RESET+'Certificate - '+Colors.BLUE+'Trying to connect'+Colors.RESET,
                join(Location, 'Logs')
            )

            # Scan_Certificate
            Dict_Result['Certificate'][url] = Check_Certificate(url, t_seconds, Host_Name, Location)
            Dict_Temp['Certificate'][url]   = Dict_Result['Certificate'][url]
            if (Host_Name == ""):
                Standard.Write_Output_File('affected_certificate_targets.txt', f'{url} (-)', Location)
            else:
                Standard.Write_Output_File('affected_certificate_targets.txt', f'{url} ({Host_Name})', Location)

            # Trace_End
            Logs.Trace_File(
                Colors.ORANGE+f'{url}'+Colors.RED+' <- '+Colors.RESET+'Certificate - '+Colors.GREEN+'OK'+Colors.RESET,
                join(Location, 'Logs')
            )


        # Cookie_Security_Flags
        if (dict_switch['scan_header']           == False and
              dict_switch['scan_security_flags'] != False and
              '//' in url and
              'http' in url):
                    # Library_Import
                    from ..Workfiles.Scan_Cookie import Check_Security_Flags

                    # Trace_Start
                    Logs.Trace_File(
                        Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                        +Colors.ORANGE+f'{url}'+Colors.RED+' -> '+Colors.RESET+'Cookie-Flags - '+Colors.BLUE+'Trying to connect'+Colors.RESET,
                        join(Location, 'Logs')
                    )

                    # Scan_Security_Flags
                    Dict_Result['Security_Flag'][url] = Check_Security_Flags(url, t_seconds, Host_Name, dict_proxies, dict_auth, Location, allow_redirects)
                    Dict_Temp['Security_Flag'][url]   = Dict_Result['Security_Flag'][url]
                    if (Host_Name == ""):
                        Standard.Write_Output_File('affected_security_flags_targets.txt', f'{url} (-)', Location)
                    else:
                        Standard.Write_Output_File('affected_security_flags_targets.txt', f'{url} ({Host_Name})', Location)

                    # Trace_End
                    Logs.Trace_File(
                        Colors.ORANGE+f'{url}'+Colors.RED+' <- '+Colors.RESET+'Cookie-Flags - '+Colors.GREEN+'OK'+Colors.RESET,
                        join(Location, 'Logs')
                    )

        # Header
        elif (dict_switch['scan_header']         != False and
              dict_switch['scan_security_flags'] == False and
              '//' in url and
              'http' in url):
                    # Library_Import
                    from ..Workfiles.Scan_Header import Check_Site_Header

                    # Trace_Start
                    Logs.Trace_File(
                        Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                        +Colors.ORANGE+f'{url}'+Colors.RED+' -> '+Colors.RESET+'Header - '+Colors.BLUE+'Trying to connect'+Colors.RESET,
                        join(Location, 'Logs')
                    )

                    # Scan_Header
                    Dict_Result['Header'][url], Dict_Result['Information'][url] = Check_Site_Header(url, t_seconds, Host_Name, dict_proxies, dict_auth, Location, allow_redirects)
                    Dict_Temp['Header'][url], Dict_Temp['Information'][url]     = Dict_Result['Header'][url], Dict_Result['Information'][url]
                    if (Host_Name == ""):
                        Standard.Write_Output_File('affected_header_targets.txt', f'{url} (-)', Location)
                        Standard.Write_Output_File('affected_http_information_disclosure_targets.txt', f'{url} (-)', Location)
                    else:
                        Standard.Write_Output_File('affected_header_targets.txt', f'{url} ({Host_Name})', Location)
                        Standard.Write_Output_File('affected_http_information_disclosure_targets.txt', f'{url} ({Host_Name})', Location)

                    # Trace_End
                    Logs.Trace_File(
                        Colors.ORANGE+f'{url}'+Colors.RED+' <- '+Colors.RESET+'Header - '+Colors.GREEN+'OK'+Colors.RESET,
                        join(Location, 'Logs')
                    )


        # Cookie_Security_Flags_And_Header
        elif (dict_switch['scan_header']         != False and
              dict_switch['scan_security_flags'] != False and
              '//' in url and
              'http' in url):
                    # Library_Import
                    from ..Workfiles.Scan_Cookie_And_HTTP_Header import Check_Cookie_And_HTTP_Header

                    # Trace_Start
                    Logs.Trace_File(
                        Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                        +Colors.ORANGE+f'{url}'+Colors.RED+' -> '+Colors.RESET+'Cookie_And_HTTP_Header - '+Colors.BLUE+'Trying to connect'+Colors.RESET,
                        join(Location, 'Logs')
                    )

                    # Scan_Header
                    Dict_Result['Security_Flag'][url], Dict_Result['Header'][url], Dict_Result['Information'][url] = Check_Cookie_And_HTTP_Header(url, t_seconds, Host_Name, dict_proxies, dict_auth, Location, allow_redirects)
                    Dict_Temp['Security_Flag'][url],   Dict_Temp['Header'][url],   Dict_Temp['Information'][url]   = Dict_Result['Security_Flag'][url], Dict_Result['Header'][url], Dict_Result['Information'][url]
                    if (Host_Name == ""):
                        Standard.Write_Output_File('affected_header_targets.txt', f'{url} (-)', Location)
                        Standard.Write_Output_File('affected_security_flags_targets.txt', f'{url} (-)', Location)
                        Standard.Write_Output_File('affected_http_information_disclosure_targets.txt', f'{url} (-)', Location)
                    else:
                        Standard.Write_Output_File('affected_header_targets.txt', f'{url} ({Host_Name})', Location)
                        Standard.Write_Output_File('affected_security_flags_targets.txt', f'{url} ({Host_Name})', Location)
                        Standard.Write_Output_File('affected_http_information_disclosure_targets.txt', f'{url} (-)', Location)

                    # Trace_End
                    Logs.Trace_File(
                        Colors.ORANGE+f'{url}'+Colors.RED+' <- '+Colors.RESET+'Cookie_And_HTTP_Header - '+Colors.GREEN+'OK'+Colors.RESET,
                        join(Location, 'Logs')
                    )

        # HTTP_Methods
        if (dict_switch['scan_http_methods'] != False and '//' in url and 'http' in url):
            # Library_Import
            from ..Workfiles.Scan_HTTP_Methods import Check_HTTP_Methods

            # Trace_Start
            Logs.Trace_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.ORANGE+f'{url}'+Colors.RED+' -> '+Colors.RESET+'HTTP-Methods - '+Colors.BLUE+'Trying to connect'+Colors.RESET,
                join(Location, 'Logs')
            )

            # Scan_HTTP_Methods
            Dict_Result['HTTP_Methods'][url] = Check_HTTP_Methods(url, Host_Name, dict_proxies, dict_auth, Location)
            Dict_Temp['HTTP_Methods'][url]   = Dict_Result['HTTP_Methods'][url]
            if (Host_Name == ""):
                Standard.Write_Output_File('affected_http_methods_targets.txt', f'{url} (-)', Location)
            else:
                Standard.Write_Output_File('affected_http_methods_targets.txt', f'{url} ({Host_Name})', Location)

            # Trace_End
            Logs.Trace_File(
                Colors.ORANGE+f'{url}'+Colors.RED+' <- '+Colors.RESET+'HTTP-Methods - '+Colors.GREEN+'OK'+Colors.RESET,
                join(Location, 'Logs')
            )


        # Screenshot
        if (dict_switch['scan_screenshot'] != None and '//' in url and 'http' in url):
            # Library_Import
            from ..Workfiles.Scan_Screen import Take_Screenshot

            # Trace_Start
            Logs.Trace_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.ORANGE+f'{url}'+Colors.RED+' -> '+Colors.RESET+'Screenshot - '+Colors.BLUE+'Trying to connect'+Colors.RESET,
                join(Location, 'Logs')
            )

            # Take_Screenshot
            Take_Screenshot(url, dict_switch['scan_screenshot'], screen_dir, switch_internet_connection, screenshot_wait, webdriver_timeout)

            # Trace_End
            Logs.Trace_File(
                Colors.ORANGE+f'{url}'+Colors.RED+' <- '+Colors.RESET+'Screenshot - '+Colors.GREEN+'OK'+Colors.RESET,
                join(Location, 'Logs')
            )


        # SMTP
        if (dict_switch['scan_smtp'] != False and 'smtp://' in url):
            pass
            #Dict_Result['SMTP'][url] = Check_SMTP.(url, t_seconds, Host_Name)


        # SSH
        if (dict_switch['scan_ssh'] != False and 'ssh://' in url):
            try: Dict_Result['SSH'][url] = SSH_Vulns(url)
            except SSHException: Logs.Write_Log(url, Host_Name, join(Location, 'Logs'))

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

    except (ConnectionError, gaierror, WebDriverException, RequestException):
        Logs.Write_Log(url, Host_Name, join(Location, 'Logs'))
    finally:
        queue.put(Dict_Result)
