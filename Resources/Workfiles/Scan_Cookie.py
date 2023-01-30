#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from Resources.Header_Files.Variables import *
from Resources.Standard_Operations.Logs import Logs
from Resources.Colors import Colors

def Check_Security_Flags(url, t_seconds, Host_Name, Dict_Temp = {}, Switch_SameSite = False):
    s = Session()
    r = s.get(url, timeout=(t_seconds, t_seconds), verify=False, allow_redirects=True)

    if (Host_Name != ""): Dict_Temp['DNS'] = Host_Name
    else: Dict_Temp['DNS'] = ""

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
                    else: Dict_Temp[Flag] = Flag
    if ('SAMESITE' not in Dict_Temp and 'HTTPONLY' not in Dict_Temp and 'SECURITY' not in Dict_Temp):
        Dict_Temp['SAMESITE'], Dict_Temp['HTTPONLY'], Dict_Temp['SECURITY'] = "FEHLT","FEHLT","FEHLT"

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

    if (Host_Name != ""): Logs.Log_File(Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'+Colors.BLUE+'Cookie-Check\n'+Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'+Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - {Host_Name} - '+Colors.CYAN+f'{r}'+Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'+Colors.ORANGE+'\nOriginal Output'+Colors.RED+' -> '+Colors.RESET+f'{r.headers.items()}'+Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'+Colors.ORANGE+'\nEinherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp}\n\n')
    else: Logs.Log_File(Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'+Colors.BLUE+'Cookie-Check\n'+Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'+Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - '+Colors.CYAN+f'{r}'+Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'+Colors.ORANGE+'\nOriginal Output'+Colors.RED+' -> '+Colors.RESET+f'{r.headers.items()}'+Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'+Colors.ORANGE+'\nEinherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp}\n\n')

    return Dict_Temp
