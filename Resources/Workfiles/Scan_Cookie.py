#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

def Check_Security_Flags(url, t_seconds, Host_Name, Dict_Temp = {}):
    s = Session()
    r = s.get(url, timeout=(t_seconds, t_seconds), verify=False, allow_redirects=True)

    if (Host_Name != ""): Dict_Temp['DNS'] = Host_Name
    else: Dict_Temp['DNS'] = ""

    # Normal_Cookie
    for Header_Key, Header_Values in r.headers.items():
        if ("COOKIE" in Header_Key.upper()):
            for Flag in Array_Security_Flags:
                if (Flag not in Header_Values): Dict_Temp[Flag] = "FEHLT"
                else:
                    if ("SAMESITE" in Header_Values):
                        if ("SAMESITE=LAX" in Header_Values or "SAMESITE=STRICT" in Header_Values): Dict_Temp[Flag] = Flag
                        else: Dict_Temp[Flag] = "FEHLT"
                    else: Dict_Temp[Flag] = Flag

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

    if (Host_Name != ""): Logs.Log_File(Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - {Host_Name} - '+Colors.BLUE+f'{r}'+Colors.ORANGE+'\nOriginal Output'+Colors.RED+' -> '+Colors.RESET+f'{r.headers.items()}'+Colors.ORANGE+'\nEinherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp}\n')
    else: Logs.Log_File(Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - '+Colors.BLUE+f'{r}'+Colors.ORANGE+'\nOriginal Output'+Colors.RED+' -> '+Colors.RESET+f'{r.headers.items()}'+Colors.ORANGE+'\nEinherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp}\n')

    return Dict_Temp
