#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

def Test(Count_Double_Point = 0, Host_Name = ""):
    Dict_Temp_Header, Dict_Temp_Information_Disclosure = {},{}
    try:
        r = get(url, timeout=(t_seconds, t_seconds), verify=False, allow_redirects=True)
        # Host_Name_Filtering
        Host_Name = Get_Host_Name(url)
        if (Host_Name != ""):
            Dict_Temp_Header['DNS'], Dict_Temp_Information_Disclosure['DNS'] = Host_Name, Host_Name
        else: Dict_Temp_Header['DNS'], Dict_Temp_Information_Disclosure['DNS'] = "",""
        # Header_Check
        for Header in r.headers.items():
            if (Header[0] in Array_Header): Dict_Temp_Header[Header[0]] = Header[1]
            elif (Header[0] in Array_Information_Disclosure_Header): Dict_Temp_Information_Disclosure[Header[0]] = Header[1]
            else:
                for Temp_Header in array(Array_Header):
                    if (Temp_Header not in Dict_Temp_Header): Dict_Temp_Header[Temp_Header] = "FEHLT"
            Dict_Result['Header'][url] = Dict_Temp_Header
            if (len(Dict_Temp_Information_Disclosure) > 0): Dict_Result['Information'][url] = Dict_Temp_Information_Disclosure
        if (Host_Name != ""): Logs.Log_File(Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - {Host_Name} - '+Colors.BLUE+f'{r}'+Colors.ORANGE+'\nOriginal Output'+Colors.RED+' -> '+Colors.RESET+f'{r.headers.items()}'+Colors.ORANGE+'\n Einherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp_Header}\n')
        else: Logs.Log_File(Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - '+Colors.BLUE+f'{r}'+Colors.ORANGE+'\nOriginal Output'+Colors.RED+' -> '+Colors.RESET+f'{r.headers.items()}'+Colors.ORANGE+'\n Einherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp_Header}\n')
    except ReadTimeout: Logs.Write_Log(url, Host_Name)
