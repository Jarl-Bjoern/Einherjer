#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def Host_Swap(Word, T_Switch = ""):
    T_Switch = Word[:-1]
    Word = T_Switch
    return Word

def Filter_Host_Name(Element, Target, Array_Temp, Word):
    if (Element != Array_Temp[len(Array_Temp)-1] and Element != Target): Word += f"{Element}, "
    elif (Element != Array_Temp[len(Array_Temp)-1] and Element == Target): pass
    elif (Element == Array_Temp[len(Array_Temp)-1] and Element == Target):
        if (Word[-1] == ","): Word = Host_Swap(Word)
    elif (Element == Array_Temp[len(Array_Temp)-1] and Element != Target): Word += f"{Element}"
    return Word

def Get_Host_Name(url, Target = "", Temp = "", Word = ""):
    if ('//' in url):
        if (url.count(':') == 2): Target = url.split('//')[1].split(':')[0]
        else: Target = url.split('//')[1]
    else: Target = url

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
                if (type(_) != list): Word = Filter_Host_Name(_, Target, Temp, Word)
#                    if (_ != Temp[len(Temp)-1] and _ != Target): Word += f"{_}, "
#                    elif (_ != Temp[len(Temp)-1] and _ == Target): pass
#                    elif (_ == Temp[len(Temp)-1] and _ == Target):
#                        if (Word[-1] == ","):
#                            T_Switch = Target[:-1]
#                            Word = T_Switch
#                    elif (_ == Temp[len(Temp)-1] and _ != Target): Word += f"{_}"
                else:
                    for j in _:
#                        Word = Filter_Host_Name(j, Target, _, Word)
                        if (j != _[len(_)-1] and j != Target): Word += f"{j}, "
                        elif (j != _[len(_)-1] and j == Target): pass
                        elif (j == _[len(_)-1] and j == Target):
                            if (Word[-1] == ","): Word = Host_Swap(Word)
                        elif (j == _[len(_)-1] and j != Target):
                            if (_ != Temp[len(Temp)-1] and _ != Target): Word += f"{j}, "
                            elif (_ != Temp[len(Temp)-1] and _ == Target): pass
                            elif (_ == Temp[len(Temp)-1] and _ == Target):
                                if (Word[-1] == ","): Word = Host_Swap(Word)
                            elif (_ == Temp[len(Temp)-1] and _ != Target): Word += f"{j}"
    elif (type(Temp) == str): Word = Temp
    return Word
