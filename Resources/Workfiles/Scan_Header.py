#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

def Scan_Header(url, t_seconds, Host_Name, Dict_Temp_Header = {}, Dict_Temp_Information_Disclosure = {}):
    try:
        r = get(url, timeout=(t_seconds, t_seconds), verify=False, allow_redirects=True)
        if (Host_Name != ""): Dict_Temp_Header['DNS'], Dict_Temp_Information_Disclosure['DNS'] = Host_Name, Host_Name
        else: Dict_Temp_Header['DNS'], Dict_Temp_Information_Disclosure['DNS'] = "",""

        for Header in r.headers.items():
            if (Header[0].upper() in Array_Header): Dict_Temp_Header[Header[0].upper()] = Header[1].upper()
            elif (Header[0].upper() in Array_Information_Disclosure_Header): Dict_Temp_Information_Disclosure[Header[0].upper()] = Header[1]
            else:
                for Temp_Header in array(Array_Header):
                    if (Temp_Header not in Dict_Temp_Header): Dict_Temp_Header[Temp_Header] = "FEHLT"
        if (Host_Name != ""): Logs.Log_File(Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - {Host_Name} - '+Colors.BLUE+f'{r}'+Colors.ORANGE+'\nOriginal Output'+Colors.RED+' -> '+Colors.RESET+f'{r.headers.items()}'+Colors.ORANGE+'\n Einherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp_Header}\n')
        else: Logs.Log_File(Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - '+Colors.BLUE+f'{r}'+Colors.ORANGE+'\nOriginal Output'+Colors.RED+' -> '+Colors.RESET+f'{r.headers.items()}'+Colors.ORANGE+'\n Einherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp_Header}\n')
    except ReadTimeout: Logs.Write_Log(url, Host_Name)

    return Dict_Temp_Header, Dict_Temp_Information_Disclosure
