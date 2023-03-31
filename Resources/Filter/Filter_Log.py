#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def Log_Filter():
    Dict_Test, Dict_Temp = {'HTTP-Information-Disclosure': {}, 'Header-Check': {}, 'Cookie-Check': {}}, {}

    with open(argv[1], 'r') as f:
            Text = f.read().splitlines()

    for _ in range(0, len(Text)):
            if ("Header-Check" in Text[_] or "HTTP-Information-Disclosure" in Text[_] or "Cookie-Check" in Text[_]):
                    Liste_Temp = resplit("{|}|'|,", Text[_+6][29:].splitlines()[0])
                    for i in range(0, len(Liste_Temp)):
                            if (Liste_Temp[i] != '' and Liste_Temp[i] != ' '):
                                    if (len(Liste_Temp[i]) > 2 and len(Liste_Temp[i+2]) > 2):
                                            Dict_Temp[Liste_Temp[i]] = Liste_Temp[i+2]
                    Dict_Test[str(Text[_][5:])][Text[_+2].split(' ')[3]] = Dict_Temp
                    Dict_Temp = {}

    return Dict_Test
