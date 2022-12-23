#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from Resources.VF import *

def Markdown_Table(Dict_Result, location, Array_Files = []):
    if (Dict_Result['Header'] != {}):
        Array_Files.append(join(location, 'result_header.md'))
        with open(join(location, 'result_header.md'), 'w', encoding='UTF-8', newline='') as md_file:
            pass
    if (Dict_Result['Information'] != {}):
        pass
    if (Dict_Result['Security_Flag'] != {}):
        pass
    if (Dict_Result['SSH'] != {}):
        pass
        
    return Array_Files
