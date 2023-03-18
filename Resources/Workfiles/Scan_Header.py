#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *
from ..Standard_Operations.Logs import Logs
from ..Standard_Operations.Colors import Colors

def Check_Site_Header(url, t_seconds, Host_Name, Dict_Proxies, Dict_Auth, Dict_Temp_Header = {}, Dict_Temp_Information_Disclosure = {}):
    try:
        # Auth_Configuration
        if (Dict_Auth['pkcs12_cert'] != ''):
            if (Dict_Proxies['http'] != '' or Dict_Proxies['https'] != ''):
                r = pkcs_get(
                    url,
                    timeout=(t_seconds, t_seconds),
                    verify=False,
                    allow_redirects=True,
                    proxies=Dict_Proxies,
                    pkcs12_filename=Dict_Auth['pkcs12_cert'],
                    pkcs12_password=Dict_Auth['pkcs12_password']
                )

            elif (Dict_Proxies['http'] == '' and Dict_Proxies['https'] == ''):
                r = pkcs_get(
                    url,
                    timeout=(t_seconds, t_seconds),
                    verify=False,
                    allow_redirects=True,
                    pkcs12_filename=Dict_Auth['pkcs12_cert'],
                    pkcs12_password=Dict_Auth['pkcs12_password']
                )
        else:
            if (Dict_Auth['user'] != '' and (Dict_Proxies['http'] != '' or Dict_Proxies['https'] != '')):
                r = get(
                    url,
                    timeout=(t_seconds, t_seconds),
                    verify=False,
                    allow_redirects=True,
                    proxies=Dict_Proxies,
                    auth=(Dict_Auth['user'],Dict_Auth['password'])
                )

            elif (Dict_Auth['user'] != '' and (Dict_Proxies['http'] == '' and Dict_Proxies['https'] == '')):
                r = get(
                    url,
                    timeout=(t_seconds, t_seconds),
                    verify=False,
                    allow_redirects=True,
                    auth=(Dict_Auth['user'], Dict_Auth['password'])
                )

            elif (Dict_Auth['user'] == '' and (Dict_Proxies['http'] != '' or Dict_Proxies['https'] != '')):
                r = get(
                    url,
                    timeout=(t_seconds, t_seconds),
                    verify=False,
                    allow_redirects=True,
                    proxies=Dict_Proxies
                )

            elif (Dict_Auth['user'] == '' and (Dict_Proxies['http'] == '' and Dict_Proxies['https'] == '')):
                r = get(
                    url,
                    timeout=(t_seconds, t_seconds),
                    verify=False,
                    allow_redirects=True
                )

        # Get_Host_Name
        if (Host_Name != ""):
            Dict_Temp_Header['DNS'], Dict_Temp_Information_Disclosure['DNS'] = Host_Name, Host_Name
        else:
            Dict_Temp_Header['DNS'], Dict_Temp_Information_Disclosure['DNS'] = "",""

        # Scanning_Process
        for Header in r.headers.items():
            # Check_Header
            if (Header[0].upper() in Dict_Header):
                Temp_Head = Header[0].upper()
                if (type(Dict_Header[Temp_Head]) == str):
                    print (Header[1].upper())
                    print (Dict_Header[Temp_Head])
                    if (Header[1].upper() in Dict_Header[Temp_Head]):
                        Dict_Temp_Header[Temp_Head] = Header[1].upper()

                elif (type(Dict_Header[Temp_Head]) == list):
                    Check_Counter = 0
                    for _ in Dict_Header[Temp_Header]:
                        if (_ in Header[1].upper()):
                            Check_Counter += 1

                    if (Check_Counter == len(Dict_Header[Temp_Header])):
                        Dict_Temp_Header[Temp_Head] = Header[1].upper()
                    else:
                        Dict_Temp_Header[Temp_Head] = "FEHLT"

            # Check_HTTP_Information_Header
            elif (Header[0].upper() in Array_Information_Disclosure_Header):
                Dict_Temp_Information_Disclosure[Header[0].upper()] = Header[1]

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
                +Colors.ORANGE+'\nEinherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp_Header}\n\n'
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
                    +Colors.ORANGE+'\nEinherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp_Information_Disclosure}\n\n'
                )
        else:
            Logs.Log_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.BLUE+'Header-Check\n'
                +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - '+Colors.CYAN+f'{r}'
                +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
                +Colors.ORANGE+'\nOriginal Output'+Colors.RED+' -> '+Colors.RESET+f'{r.headers.items()}'
                +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
                +Colors.ORANGE+'\nEinherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp_Header}\n\n'
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
                    +Colors.ORANGE+'\nEinherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp_Information_Disclosure}\n\n'
                )

        # Terminate_Session
        r.close()

    except ReadTimeout:
        Logs.Write_Log(url, Host_Name)

    return Dict_Temp_Header, Dict_Temp_Information_Disclosure
