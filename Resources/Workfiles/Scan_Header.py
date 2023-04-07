#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *
from ..Standard_Operations.Logs import Logs
from ..Standard_Operations.Colors import Colors
from ..Standard_Operations.Standard import Standard

def Check_Site_Header(url, t_seconds, Host_Name, Dict_Proxies, Dict_Auth, Location, Allow_Redirects, Dict_Temp_Header = {}, Dict_Temp_Information_Disclosure = {}, Dict_Temp_Deprecated_Header = {}):
    try:
        # Auth_Configuration
        if (Dict_Auth['pkcs12_cert'] != ''):
            if (Dict_Proxies['http'] != '' or Dict_Proxies['https'] != ''):
                r = pkcs_get(
                    url,
                    timeout=(t_seconds, t_seconds),
                    verify=False,
                    allow_redirects=Allow_Redirects,
                    proxies=Dict_Proxies,
                    pkcs12_filename=Dict_Auth['pkcs12_cert'],
                    pkcs12_password=Dict_Auth['pkcs12_password']
                )

            elif (Dict_Proxies['http'] == '' and Dict_Proxies['https'] == ''):
                r = pkcs_get(
                    url,
                    timeout=(t_seconds, t_seconds),
                    verify=False,
                    allow_redirects=Allow_Redirects,
                    pkcs12_filename=Dict_Auth['pkcs12_cert'],
                    pkcs12_password=Dict_Auth['pkcs12_password']
                )
        else:
            if (Dict_Auth['user'] != '' and (Dict_Proxies['http'] != '' or Dict_Proxies['https'] != '')):
                r = get(
                    url,
                    timeout=(t_seconds, t_seconds),
                    verify=False,
                    allow_redirects=Allow_Redirects,
                    proxies=Dict_Proxies,
                    auth=(Dict_Auth['user'],Dict_Auth['password'])
                )

            elif (Dict_Auth['user'] != '' and (Dict_Proxies['http'] == '' and Dict_Proxies['https'] == '')):
                r = get(
                    url,
                    timeout=(t_seconds, t_seconds),
                    verify=False,
                    allow_redirects=Allow_Redirects,
                    auth=(Dict_Auth['user'], Dict_Auth['password'])
                )

            elif (Dict_Auth['user'] == '' and (Dict_Proxies['http'] != '' or Dict_Proxies['https'] != '')):
                r = get(
                    url,
                    timeout=(t_seconds, t_seconds),
                    verify=False,
                    allow_redirects=Allow_Redirects,
                    proxies=Dict_Proxies
                )

            elif (Dict_Auth['user'] == '' and (Dict_Proxies['http'] == '' and Dict_Proxies['https'] == '')):
                r = get(
                    url,
                    timeout=(t_seconds, t_seconds),
                    verify=False,
                    allow_redirects=Allow_Redirects
                )

        # Get_Host_Name
        if (Host_Name != ""):
            Dict_Temp_Header['DNS'], Dict_Temp_Information_Disclosure['DNS'] = Host_Name, Host_Name
        else:
            Dict_Temp_Header['DNS'], Dict_Temp_Information_Disclosure['DNS'] = "",""

        # Scanning_Process
        for Header_Key, Header_Values in r.headers.items():
            # Check_Header
            if (Header_Key.upper() in Dict_Header):
                Temp_Head = Header_Key.upper()
                if (type(Dict_Header[Temp_Head]) == str):
                    if (Header_Values.upper() == Dict_Header[Temp_Head]):
                        Dict_Temp_Header[Temp_Head] = Header_Values.upper()

                elif (type(Dict_Header[Temp_Head]) == list):
                    Check_Counter = 0
                    for _ in Dict_Header[Temp_Head]:
                        if (_ in Header_Values.upper()):
                            Check_Counter += 1

                    if (Check_Counter == len(Dict_Header[Temp_Head])):
                        Dict_Temp_Header[Temp_Head] = Header_Values.upper()
                    elif (Dict_Header[Temp_Head] != "CONTENT-SECURITY-POLICY" and
                          Dict_Header[Temp_Head] != "STRICT-TRANSPORT-SECURITY" and
                          Check_Counter > 0):
                                Dict_Temp_Header[Temp_Head] = Header_Values.upper()
                    else:
                        Dict_Temp_Header[Temp_Head] = "FEHLT"

            # Check_HTTP_Information_Header
            elif (Header_Key.upper() in Array_Information_Disclosure_Header):
                Dict_Temp_Information_Disclosure[Header_Key.upper()] = Header_Values

            # Check_For_Missing_Header
            else:
                for Temp_Header in array(list(Dict_Header)):
                    if (Temp_Header not in Dict_Temp_Header):
                        Dict_Temp_Header[Temp_Header] = "FEHLT"

        # Logging
        if (Host_Name != ""):
            Logs.Log_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.BLUE+'Header-Check\n'
                +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - {Host_Name} - '+Colors.CYAN+f'{r}'
                +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
                +Colors.ORANGE+'\nOriginal Output'+Colors.RED+' -> '+Colors.RESET+f'{r.headers.items()}'
                +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
                +Colors.ORANGE+'\nEinherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp_Header}\n\n',
                join(Location, 'Logs')
            )
            if (len(Dict_Temp_Information_Disclosure) > 1):
                Logs.Log_File(
                    Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                    +Colors.BLUE+'HTTP-Information-Disclosure\n'
                    +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                    +Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - {Host_Name} - '+Colors.CYAN+f'{r}'
                    +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
                    +Colors.ORANGE+'\nOriginal Output'+Colors.RED+' -> '+Colors.RESET+f'{r.headers.items()}'
                    +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
                    +Colors.ORANGE+'\nEinherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp_Information_Disclosure}\n\n',
                    join(Location, 'Logs')
                )
                Standard.Write_Output_File('affected_http_information_disclosure_targets.txt', f'{url} ({Host_Name})', Location)
            Standard.Write_Output_File('affected_header_targets.txt', f'{url} ({Host_Name})', Location)
        else:
            Logs.Log_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.BLUE+'Header-Check\n'
                +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - '+Colors.CYAN+f'{r}'
                +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
                +Colors.ORANGE+'\nOriginal Output'+Colors.RED+' -> '+Colors.RESET+f'{r.headers.items()}'
                +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
                +Colors.ORANGE+'\nEinherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp_Header}\n\n',
                join(Location, 'Logs')
            )
            if (len(Dict_Temp_Information_Disclosure) > 1):
                Logs.Log_File(
                    Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                    +Colors.BLUE+'HTTP-Information-Disclosure\n'
                    +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                    +Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - '+Colors.CYAN+f'{r}'
                    +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
                    +Colors.ORANGE+'\nOriginal Output'+Colors.RED+' -> '+Colors.RESET+f'{r.headers.items()}'
                    +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
                    +Colors.ORANGE+'\nEinherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp_Information_Disclosure}\n\n',
                    join(Location, 'Logs')
                )
                Standard.Write_Output_File('affected_http_information_disclosure_targets.txt', f'{url} (-)', Location)
            Standard.Write_Output_File('affected_header_targets.txt', f'{url} (-)', Location)

        # Terminate_Session
        r.close()


    except ReadTimeout:
        Logs.Write_Log(url, Host_Name, join(Location, 'Logs'))

    return Dict_Temp_Header, Dict_Temp_Information_Disclosure
