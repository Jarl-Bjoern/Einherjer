#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables       import *
from ..Standard_Operations.Logs     import Logs
from ..Standard_Operations.Colors   import Colors
from ..Standard_Operations.Standard import Standard

class Get_Information:
    def Check_Website(url, t_seconds, Dict_Temp = {}, Array_Output = [], Temp_Array = []):
        Array_Filter = ["Apache/", "Tomcat/", "Server Version:"]

        with open('/opt/test.txt', 'w') as f:
             for i in array(Read_File(argv[1])):
                 r = get(str(i), verify=False, timeout=(25,25))
                 for _ in array(Array_Filter):
                     x = search(rf'^.*{_}.*', str(r.content))
                     if (x != None):
                        for j in array(r.text.splitlines()):
                            if (_ in j):
                                Temp_Array = resplit("<dl>|<dt>|</dt>", j)
                                if (len(Temp_Array) > 1):
                                    for k in array(Temp_Array):
                                        if (len(k) > 1):
                                            if (f'{i} - {k}' not in Array_Output): Array_Output.append(f'{i} - {k}')

        return Dict_Temp
