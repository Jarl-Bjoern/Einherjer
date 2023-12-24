#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def Responder_Logs(responder_files_location, output_location, Dict_System = {}, Array_Temp = [], Array_Output = []):
    try:
        # Check_For_One_File
        if (isfile(responder_files_location)):
            if (responder_files_location.endswith('.log') and "Responder-Session" in responder_files_location):
                with open(responder_files_location, 'r') as f:
                    Text = f.read().splitlines()

                for i in Text:
                    if ("Username" in i):
                        print (i)
                    elif ("MDNS" in i):
                        print (f"{i.split(' ')[10]} ({i.split(' ')[12]})")

            elif (responder_file.endswith('.txt') and "Responder-Session" in responder_files_location):
                pass

        # Check_For_Multiple_Files
        elif (isdir(responder_files_location)):
            for responder_file in listdir(responder_files_location):
                if (responder_file.endswith('.log') and "Responder-Session" in responder_file):
                    pass
                elif (responder_file.endswith('.txt') and "Responder-Session" in responder_file):
                    pass

        Array_Temp.append(join(output_location, 'mitm-overview.csv'))
        with open(join(output_location, 'mitm-overview.csv'), 'w') as f:
             f.write("LLMNR;MDNS;USER\n")
             for i in Dict_System:
                 f.write(f'{i};')
                 for j in Dict_System[i]:
                     for k in range(0, len(Dict_System[i][j])):
                         if (k != len(Dict_System[i][j])-1): f.write(f'{Dict_System[i][j][k]}, ')
                         else: f.write(f'{Dict_System[i][j][k]}')
                     f.write(f';')
                 f.write('\n')

    except FileNotFoundError:
        pass

    return Array_Temp
