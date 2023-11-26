#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables       import *
from ..Standard_Operations.Logs     import Logs
from ..Standard_Operations.Colors   import Colors
from ..Standard_Operations.Standard import Standard

def Check_CORS_Header(url, t_seconds, Host_Name, Dict_Proxies, Dict_Auth, Location, Allow_Redirects, dict_custom_header, Dict_Temp_CORS = {}):
    try
        # Session_Creation
        with Session() as s:

            # Auth_Configuration
            if (Dict_Auth['pkcs12_cert'] != ''):
                s.mount(url, Pkcs12Adapter(pkcs12_filename=Dict_Auth['pkcs12_cert'], pkcs12_password=Dict_Auth['pkcs12_password']))
                dict_custom_header['Origin'] = 'einherjer-test-scanning.vul'
                if (Dict_Proxies['http'] != '' or Dict_Proxies['https'] != ''):
                    r = s.get(
                        url,
                        timeout=(t_seconds, t_seconds),
                        headers=dict_custom_header,
                        verify=False,
                        allow_redirects=Allow_Redirects,
                        proxies=Dict_Proxies,
                        pkcs12_filename=Dict_Auth['pkcs12_cert'],
                        pkcs12_password=Dict_Auth['pkcs12_password']
                    )

                elif (Dict_Proxies['http'] == '' and Dict_Proxies['https'] == ''):
                    r = s.get(
                        url,
                        timeout=(t_seconds, t_seconds),
                        headers=dict_custom_header,
                        verify=False,
                        allow_redirects=Allow_Redirects,
                        pkcs12_filename=Dict_Auth['pkcs12_cert'],
                        pkcs12_password=Dict_Auth['pkcs12_password']
                    )
            else:
                if (Dict_Auth['user'] != '' and (Dict_Proxies['http'] != '' or Dict_Proxies['https'] != '')):
                    r = s.get(
                        url,
                        timeout=(t_seconds, t_seconds),
                        headers=dict_custom_header,
                        verify=False,
                        allow_redirects=Allow_Redirects,
                        proxies=Dict_Proxies,
                        auth=(Dict_Auth['user'], Dict_Auth['password'])
                    )

                elif (Dict_Auth['user'] != '' and (Dict_Proxies['http'] == '' and Dict_Proxies['https'] == '')):
                    r = s.get(
                        url,
                        timeout=(t_seconds, t_seconds),
                        headers=dict_custom_header,
                        verify=False,
                        allow_redirects=Allow_Redirects,
                        auth=(Dict_Auth['user'], Dict_Auth['password'])
                    )

                elif (Dict_Auth['user'] == '' and (Dict_Proxies['http'] != '' or Dict_Proxies['https'] != '')):
                    r = s.get(
                        url,
                        timeout=(t_seconds, t_seconds),
                        headers=dict_custom_header,
                        verify=False,
                        allow_redirects=Allow_Redirects,
                        proxies=Dict_Proxies
                    )

                elif (Dict_Auth['user'] == '' and (Dict_Proxies['http'] == '' and Dict_Proxies['https'] == '')):
                    r = s.get(
                        url,
                        timeout=(t_seconds, t_seconds),
                        headers=dict_custom_header,
                        verify=False,
                        allow_redirects=Allow_Redirects
                    )

        # Get_Host_Name
        if (Host_Name != ""):  Dict_Temp_CORS['DNS']  = Host_Name
        else:                  Dict_Temp_CORS['DNS']  = ""


        # Scanning_CORS_Output
        for Header_Key, Header_Values in r.headers.items():
            # Check_Header
            if (Header_Key.upper() == "ACCESS-CONTROL-ALLOW-ORIGIN"):
                Temp_Head = Header_Key.upper()
                if (Header_Values.upper() == "*"):
                    Dict_Temp_CORS[Temp_Head] = Header_Values.upper()


        # Logging
        if (Host_Name != ""):
            Logs.Log_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.BLUE+'CORS-Check\n'
                +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - {Host_Name} - '+Colors.CYAN+f'{r}'
                +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
                +Colors.ORANGE+'\nOriginal Output'+Colors.RED+' -> '+Colors.RESET+f'{r.headers.items()}'
                +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
                +Colors.ORANGE+'\nEinherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp_CORS}\n\n',
                join(Location, 'Logs')
            )
            Standard.Write_Output_File('affected_cors_targets.txt', f'{url} ({Host_Name})', Location)
        else:
            Logs.Log_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.BLUE+'CORS-Check\n'
                +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - '+Colors.CYAN+f'{r}'
                +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
                +Colors.ORANGE+'\nOriginal Output'+Colors.RED+' -> '+Colors.RESET+f'{r.headers.items()}'
                +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
                +Colors.ORANGE+'\nEinherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp_CORS}\n\n',
                join(Location, 'Logs')
            )
            Standard.Write_Output_File('affected_cors_targets.txt', f'{url} (-)', Location)


        # Terminate_Session
        r.close()


    except ReadTimeout:
        Logs.Write_Log(url, Host_Name, join(Location, 'Logs'))

    return Dict_Temp_CORS
