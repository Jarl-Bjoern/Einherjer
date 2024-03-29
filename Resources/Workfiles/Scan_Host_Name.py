#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def Host_Swap(Word, T_Switch = ""):
    T_Switch = Word[:-2]
    Word     = T_Switch
    return Word

def Filter_Host_Name(Element, Target, Array_Temp, Word):
    if (Element != Array_Temp[len(Array_Temp)-1] and Element != Target):   Word += f"{Element}, "
    elif (Element != Array_Temp[len(Array_Temp)-1] and Element == Target): pass
    elif (Element == Array_Temp[len(Array_Temp)-1] and Element == Target):
        if (Word[-2:] == ", "): Word = Host_Swap(Word)
    elif (Element == Array_Temp[len(Array_Temp)-1] and Element != Target): Word += f"{Element}"

    return Word

def Get_Host_Name(url, Target = "", Temp = "", Sec_Temp = "", Word = ""):
    # Remove_All_Protocol_Slashes_And_Colon
    if ('//' in url):
        if (url.count(':') == 2): Target = url.split('//')[1].split(':')[0]
        else:                     Target = url.split('//')[1]
    else:
        if (url.count(':') == 1): Target = url.split(':')[0]
        else:                     Target = url

    # Remove_All_Slashes
    if ('/' in Target):
        Sec_Temp = Target.split('/')[0]
        Target   = Sec_Temp

    try: Temp = gethostbyaddr(Target)
    except (gaierror, herror):
        try:
            Temp = gethostbyname(Target)
            if (Temp == Target): Temp = ""
        except (gaierror, herror, UnicodeError): pass
    except UnicodeError: pass

    if (type(Temp) == tuple or type(Temp) == list):
        for _ in Temp:
            if (_ != []):
                if (type(_) != list):
                    Word = Filter_Host_Name(_, Target, Temp, Word)
                else:
                    for j in _:
                        if (j != _[len(_)-1] and j != Target): Word += f"{j}, "
                        elif (j != _[len(_)-1] and j == Target): pass
                        elif (j == _[len(_)-1] and j == Target):
                            if (Word[-2:] == ", "): Word = Host_Swap(Word)
                        elif (j == _[len(_)-1] and j != Target):
                            if (_ != Temp[len(Temp)-1] and _ != Target): Word += f"{j}, "
                            elif (_ != Temp[len(Temp)-1] and _ == Target): pass
                            elif (_ == Temp[len(Temp)-1] and _ == Target):
                                if (Word[-2:] == ", "): Word = Host_Swap(Word)
                            elif (_ == Temp[len(Temp)-1] and _ != Target): Word += f"{j}"
    elif (type(Temp) == str): Word = Temp

    return Word
