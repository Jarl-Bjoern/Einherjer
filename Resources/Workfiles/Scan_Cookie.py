#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *
from ..Standard_Operations.Logs import Logs
from ..Standard_Operations.Colors import Colors
from ..Standard_Operations.Standard import Standard

def Check_Security_Flags(url, t_seconds, Host_Name, Dict_Proxies, Dict_Auth, Location, Allow_Redirects, Dict_Temp = {'DNS': "", 'SAMESITE': "", 'HTTPONLY': "", 'SECURE': ""}, Switch_SameSite = False):
    # Session_Creation
    with Session() as s:

        # Auth_Configuration
        if (Dict_Auth['pkcs12_cert'] != ''):
            s.mount(url, Pkcs12Adapter(pkcs12_filename=Dict_Auth['pkcs12_cert'], pkcs12_password=Dict_Auth['pkcs12_password']))
            if (Dict_Proxies['http'] != '' or Dict_Proxies['https'] != ''):
                r = s.get(
                    url,
                    timeout=(t_seconds, t_seconds),
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
                    verify=False,
                    allow_redirects=Allow_Redirects,
                    proxies=Dict_Proxies,
                    auth=(Dict_Auth['user'], Dict_Auth['password'])
                )

            elif (Dict_Auth['user'] != '' and (Dict_Proxies['http'] == '' and Dict_Proxies['https'] == '')):
                r = s.get(
                    url,
                    timeout=(t_seconds, t_seconds),
                    verify=False,
                    allow_redirects=Allow_Redirects,
                    auth=(Dict_Auth['user'], Dict_Auth['password'])
                )

            elif (Dict_Auth['user'] == '' and (Dict_Proxies['http'] != '' or Dict_Proxies['https'] != '')):
                r = s.get(
                    url,
                    timeout=(t_seconds, t_seconds),
                    verify=False,
                    allow_redirects=Allow_Redirects,
                    proxies=Dict_Proxies
                )

            elif (Dict_Auth['user'] == '' and (Dict_Proxies['http'] == '' and Dict_Proxies['https'] == '')):
                r = s.get(
                    url,
                    timeout=(t_seconds, t_seconds),
                    verify=False,
                    allow_redirects=Allow_Redirects
                )

        # Get_Host_Name
        if (Host_Name != ""): Dict_Temp['DNS'] = Host_Name
        else:                 Dict_Temp['DNS'] = ""

        # Normal_Cookie
        for Header_Key, Header_Values in r.headers.items():
            if ("COOKIE" in Header_Key.upper()):
                Target_Flags = Header_Values.upper()
                for Flag in Array_Security_Flags:
                    if (Flag not in Target_Flags): Dict_Temp[Flag] = "FEHLT"
                    else:
                        if ("SAMESITE" in Target_Flags and Switch_SameSite != True):
                            if ("SAMESITE=LAX" in Target_Flags or "SAMESITE=STRICT" in Target_Flags): Dict_Temp[Flag] = Flag
                            else: Dict_Temp[Flag] = "FEHLT"
                            Switch_SameSite = True
                        else: Dict_Temp[Flag] = Flag

        # Logging
        if (Host_Name != ""):
            Logs.Log_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.BLUE+'Cookie-Check\n'
                +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - {Host_Name} - '+Colors.CYAN+f'{r}'
                +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
                +Colors.ORANGE+'\nOriginal Output'+Colors.RED+' -> '+Colors.RESET+f'{r.headers.items()}'
                +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
                +Colors.ORANGE+'\nEinherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp}\n\n',
                join(Location, 'Logs')
            )
            Standard.Write_Output_File('affected_security_flags_targets.txt', f'{url} ({Host_Name})', Location)
        else:
            Logs.Log_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.BLUE+'Cookie-Check\n'
                +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - '+Colors.CYAN+f'{r}'
                +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
                +Colors.ORANGE+'\nOriginal Output'+Colors.RED+' -> '+Colors.RESET+f'{r.headers.items()}'
                +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
                +Colors.ORANGE+'\nEinherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp}\n\n',
                join(Location, 'Logs')
            )
            Standard.Write_Output_File('affected_security_flags_targets.txt', f'{url} (-)', Location)

        # Terminate_Session
        r.close()


    # Cookie_Jar
#    for cookie in dict(s.cookies): pass
#        for i,j in cookie.__dict__.items():
#            if ('_rest' in i):
#                print (f'{i} : {j}')

#                        try:
#                            Cookie = r.cookies.get_dict()
#                            for head in Cookie:
#                                if ('JSID' not in head):
#
#                                elif ('Test' not in head):
#                        except: pass
#
#
#                        Dict_Result['Security_Flag']

    # Empty_Filter
    if (Dict_Temp['SAMESITE'] == ""): Dict_Temp['SAMESITE'] = "FEHLT"
    if (Dict_Temp['HTTPONLY'] == ""): Dict_Temp['HTTPONLY'] = "FEHLT"
    if (Dict_Temp['SECURE'] == ""):   Dict_Temp['SECURE'] = "FEHLT"

    return Dict_Temp
