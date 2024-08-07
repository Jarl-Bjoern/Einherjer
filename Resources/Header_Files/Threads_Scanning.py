#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from .Variables import *
from ..Standard_Operations.Logs import *
from ..Standard_Operations.Colors import Colors
from ..Standard_Operations.Standard import Standard

# Functions
def Thread_Scanning_Start(url, t_seconds, queue, dict_switch, screen_dir, switch_internet_connection, screenshot_wait, webdriver_timeout, ssl_timeout, dict_proxies, dict_auth, file_format, Location, allow_redirects, screenshot_frame_thickness, driver_path, dict_custom_header, screen_frame_switch, screen_border_type, language, Host_Name = ""):
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

        # Temp_Variable
        Temp_URL_Switcher, Temp_URL_Backup = "", ""

        # Get_Host_Name
        if (dict_switch['scan_host_name'] != False):
            # Library_Import
            from ..Workfiles.Scan_Host_Name import Get_Host_Name

            # Trace_Start
            Logs.Trace_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.ORANGE+f'{url}'+Colors.RED+' -> '+Colors.CYAN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+' - Host_Name - '+Colors.BLUE+'Trying to connect'+Colors.RESET,
                join(Location, 'Logs')
            )

            # Get_Host_Name
            Host_Name = Get_Host_Name(url)
            if (url.count(':') == 2):
                Temp_Target = url.split(':')[1]
                if ('//' in Temp_Target):
                    Temp_Target = Temp_Target.split('//')[1]
            elif (url.count(':') == 1):
                Temp_Target = url.split(':')[1]
                if ('//' in Temp_Target):
                    Temp_Target = Temp_Target.split('//')[1]
            else:
                Temp_Target = url

            if (Host_Name != ""  and
                Host_Name != " " and
                Host_Name != "-"):
                    Standard.Write_Output_File('DNS_Template.txt', f'{Temp_Target}:{Host_Name}', Location)
                    Dict_Result['Hostnames'][Temp_Target] = Host_Name

            # Trace_End
            Logs.Trace_File(
                Colors.ORANGE+f'{url}'+Colors.RED+' <- '+Colors.CYAN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+' - Host_Name - '+Colors.GREEN+'OK'+Colors.RESET,
                join(Location, 'Logs')
            )


        # Certificates
        if (dict_switch['scan_certificate'] != False and ('https://' in url or 'ssl://' in url)):
            # Library_Import
            from ..Workfiles.Scan_Certificate import Check_Certificate

            # Trace_Start
            Logs.Trace_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.ORANGE+f'{url}'+Colors.RED+' -> '+Colors.CYAN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+' - Certificate - '+Colors.BLUE+'Trying to connect'+Colors.RESET,
                join(Location, 'Logs')
            )

            # Scan_Certificate
            try:
                Dict_Result['Certificate'][url] = Check_Certificate(url, t_seconds, Host_Name, Location)
                Dict_Temp['Certificate'][url]   = Dict_Result['Certificate'][url]

                # Trace_End
                Logs.Trace_File(
                    Colors.ORANGE+f'{url}'+Colors.RED+' <- '+Colors.CYAN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+' - Certificate - '+Colors.GREEN+'OK'+Colors.RESET,
                    join(Location, 'Logs')
                )
            except TimeoutError:
                Logs.Write_Log(url, Host_Name, join(Location, 'Logs'))


        # Create_URL_Backup
        Temp_URL_Backup = url

        # Get_Protocol
        if ('http://' in url):
            Protocol, Begin =  'http://', 7
        elif ('https://' in url):
            Protocol, Begin = 'https://', 8

        # Convert_With_URL_Encoding
        if (url.count('/') > 3 and '//' in url):
            Temp_URL_Switcher = url_encode(url[Begin:])
            url               = f'{Protocol}{Temp_URL_Switcher.replace("2%F", "/")}'
        elif (url.count('/') == 3 and '//' in url):
            if (url[-1:] == '/'):
                Temp_URL_Switcher = url[Begin:-1]
            else:
                Temp_URL_Switcher = url_encode(url[Begin:])
            url               = f'{Protocol}{Temp_URL_Switcher.replace("2%F", "/")}'
        elif (url.count('/') == 2 and '//' in url):
            pass

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
                        +Colors.ORANGE+f'{url}'+Colors.RED+' -> '+Colors.CYAN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+' - Cookie-Flags - '+Colors.BLUE+'Trying to connect'+Colors.RESET,
                        join(Location, 'Logs')
                    )

                    # Scan_Security_Flags
                    Dict_Result['Security_Flag'][url] = Check_Security_Flags(url, t_seconds, Host_Name, dict_proxies, dict_auth, Location, allow_redirects, dict_custom_header)
                    Dict_Temp['Security_Flag'][url]   = Dict_Result['Security_Flag'][url]

                    # Trace_End
                    Logs.Trace_File(
                        Colors.ORANGE+f'{url}'+Colors.RED+' <- '+Colors.CYAN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+' - Cookie-Flags - '+Colors.GREEN+'OK'+Colors.RESET,
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
                        +Colors.ORANGE+f'{url}'+Colors.RED+' -> '+Colors.CYAN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+' - Header - '+Colors.BLUE+'Trying to connect'+Colors.RESET,
                        join(Location, 'Logs')
                    )

                    # Scan_Header
                    Dict_Result['Header'][url], Dict_Result['Information'][url] = Check_Site_Header(url, t_seconds, Host_Name, dict_proxies, dict_auth, Location, allow_redirects, dict_custom_header)
                    Dict_Temp['Header'][url], Dict_Temp['Information'][url]     = Dict_Result['Header'][url], Dict_Result['Information'][url]

                    # Trace_End
                    Logs.Trace_File(
                        Colors.ORANGE+f'{url}'+Colors.RED+' <- '+Colors.CYAN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+' - Header - '+Colors.GREEN+'OK'+Colors.RESET,
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
                        +Colors.ORANGE+f'{url}'+Colors.RED+' -> '+Colors.CYAN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+' - Cookie_And_HTTP_Header - '+Colors.BLUE+'Trying to connect'+Colors.RESET,
                        join(Location, 'Logs')
                    )

                    # Scan_Header
                    Dict_Result['Security_Flag'][url], Dict_Result['Header'][url], Dict_Result['Information'][url] = Check_Cookie_And_HTTP_Header(url, t_seconds, Host_Name, dict_proxies, dict_auth, Location, allow_redirects, dict_custom_header)
                    Dict_Temp['Security_Flag'][url],   Dict_Temp['Header'][url],   Dict_Temp['Information'][url]   = Dict_Result['Security_Flag'][url], Dict_Result['Header'][url], Dict_Result['Information'][url]

                    # Trace_End
                    Logs.Trace_File(
                        Colors.ORANGE+f'{url}'+Colors.RED+' <- '+Colors.CYAN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+' - Cookie_And_HTTP_Header - '+Colors.GREEN+'OK'+Colors.RESET,
                        join(Location, 'Logs')
                    )


        # CORS
        if (dict_switch['scan_cors'] != False and ('https://' in url or 'ssl://' in url)):
            # Library_Import
            from ..Workfiles.Scan_CORS import Check_CORS_Header

            # Trace_Start
            Logs.Trace_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.ORANGE+f'{url}'+Colors.RED+' -> '+Colors.CYAN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+' - CORS - '+Colors.BLUE+'Trying to connect'+Colors.RESET,
                join(Location, 'Logs')
            )

            # Scan_CORS
            Dict_Result['CORS'][url] = Check_CORS_Header(url, t_seconds, Host_Name, dict_proxies, dict_auth, Location, allow_redirects, dict_custom_header)
            Dict_Temp['CORS'][url]   = Dict_Result['CORS'][url]

            # Trace_End
            Logs.Trace_File(
                Colors.ORANGE+f'{url}'+Colors.RED+' <- '+Colors.CYAN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+' - CORS - '+Colors.GREEN+'OK'+Colors.RESET,
                join(Location, 'Logs')
            )


        # HTTP_Methods
        if (dict_switch['scan_http_methods'] != False and '//' in url and 'http' in url):
            # Library_Import
            from ..Workfiles.Scan_HTTP_Methods import Check_HTTP_Methods

            # Trace_Start
            Logs.Trace_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.ORANGE+f'{url}'+Colors.RED+' -> '+Colors.CYAN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+' - HTTP-Methods - '+Colors.BLUE+'Trying to connect'+Colors.RESET,
                join(Location, 'Logs')
            )

            # Scan_HTTP_Methods
            Dict_Result['HTTP_Methods'][url] = Check_HTTP_Methods(url, t_seconds, Host_Name, dict_proxies, dict_auth, Location, allow_redirects, dict_custom_header)
            Dict_Temp['HTTP_Methods'][url]   = Dict_Result['HTTP_Methods'][url]

            # Trace_End
            Logs.Trace_File(
                Colors.ORANGE+f'{url}'+Colors.RED+' <- '+Colors.CYAN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+' - HTTP-Methods - '+Colors.GREEN+'OK'+Colors.RESET,
                join(Location, 'Logs')
            )


        # Screenshot
        if (dict_switch['scan_screenshot'] != None and '//' in url and 'http' in url):
            # Library_Import
            from ..Workfiles.Scan_Screen import Take_Screenshot

            # Trace_Start
            Logs.Trace_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.ORANGE+f'{url}'+Colors.RED+' -> '+Colors.CYAN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+' - Screenshot - '+Colors.BLUE+'Trying to connect'+Colors.RESET,
                join(Location, 'Logs')
            )

            # Take_Screenshot
            Take_Screenshot(url, dict_switch['scan_screenshot'], driver_path, screen_dir, switch_internet_connection, screenshot_wait, webdriver_timeout, screenshot_frame_thickness, screen_frame_switch, screen_border_type)

            # Trace_End
            Logs.Trace_File(
                Colors.ORANGE+f'{url}'+Colors.RED+' <- '+Colors.CYAN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+' - Screenshot - '+Colors.GREEN+'OK'+Colors.RESET,
                join(Location, 'Logs')
            )

        # Reset_URL
        url = Temp_URL_Backup

        # FTP
        if (dict_switch['scan_ftp'] != False and 'ftp://' in url):
            # Library_Import
            from ..Workfiles.Scan_FTP import Check_FTP

            # Trace_Start
            Logs.Trace_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.ORANGE+f'{url}'+Colors.RED+' -> '+Colors.CYAN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+' - Scan_FTP - '+Colors.BLUE+'Trying to connect'+Colors.RESET,
                join(Location, 'Logs')
            )

            # Scanning_Process
            Dict_Result['FTP'][url] = Check_FTP.FTP_Anonymous_Check(url, Host_Name, Location)
            Dict_Temp['FTP'][url]   = Dict_Result['FTP'][url]

            # Trace_End
            Logs.Trace_File(
                Colors.ORANGE+f'{url}'+Colors.RED+' <- '+Colors.CYAN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+' - Scan_FTP - '+Colors.GREEN+'OK'+Colors.RESET,
                join(Location, 'Logs')
            )


        # SMTP
        if (dict_switch['scan_smtp'] != False and 'smtp://' in url):
            # Library_Import
            from ..Workfiles.Scan_SMTP import Check_SMTP

            # Trace_Start
            Logs.Trace_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.ORANGE+f'{url}'+Colors.RED+' -> '+Colors.CYAN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+' - Scan_SMTP - '+Colors.BLUE+'Trying to connect'+Colors.RESET,
                join(Location, 'Logs')
            )

            # Scanning_Process
            pass
            #Dict_Result['SMTP'][url] = Check_SMTP.Check_Open_Relay(url, sender, receiver, message)
            #Dict_Temp['SMTP'][url]   = Dict_Result['SMTP'][url]

            # Trace_End
            Logs.Trace_File(
                Colors.ORANGE+f'{url}'+Colors.RED+' <- '+Colors.CYAN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+' - Scan_SMTP - '+Colors.GREEN+'OK'+Colors.RESET,
                join(Location, 'Logs')
            )


        # SNMP
        if (dict_switch['scan_snmp'] != False and 'snmp://' in url):
            # Library_Import
            from ..Workfiles.Scan_SNMP import Check_SNMP

            # Trace_Start
            Logs.Trace_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.ORANGE+f'{url}'+Colors.RED+' -> '+Colors.CYAN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+' - Check_SNMP - '+Colors.BLUE+'Trying to connect'+Colors.RESET,
                join(Location, 'Logs')
            )

            # Scanning_Process
            #Dict_Result['SNMP'][url] = Check_SNMP.Basic_Check(url, t_seconds, Host_Name, Location)
            #Dict_Temp['SNMP'][url]   = Dict_Result['SNMP'][url]

            # Trace_End
            Logs.Trace_File(
                Colors.ORANGE+f'{url}'+Colors.RED+' <- '+Colors.CYAN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+' - Check_SNMP - '+Colors.GREEN+'OK'+Colors.RESET,
                join(Location, 'Logs')
            )


        # SSH
        if (dict_switch['scan_ssh'] != False and 'ssh://' in url):
            # Library_Import
            from ..Workfiles.Scan_SSH import SSH_Vulns

            # Trace_Start
            Logs.Trace_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.ORANGE+f'{url}'+Colors.RED+' -> '+Colors.CYAN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+' - Scan_SSH - '+Colors.BLUE+'Trying to connect'+Colors.RESET,
                join(Location, 'Logs')
            )

            # Scanning_Process
            Dict_Result['SSH'][url] = SSH_Vulns(url, t_seconds, Host_Name, Location)
            Dict_Temp['SSH'][url]   = Dict_Result['SSH'][url]

            # Trace_End
            Logs.Trace_File(
                Colors.ORANGE+f'{url}'+Colors.RED+' <- '+Colors.CYAN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+' - Scan_SSH - '+Colors.GREEN+'OK'+Colors.RESET,
                join(Location, 'Logs')
            )


        # Write_File_Format
        file_format(Dict_Temp, Location, language)

    except (ConnectionError, gaierror, RequestException, SSLError, TimeoutError, WebDriverException):
        Logs.Write_Log(url, Host_Name, join(Location, 'Logs'))
    finally:
        queue.put(Dict_Result, block=False, timeout=30)
