#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def Responder_Logs(responder_files_location, output_location, Array_Temp = []):
    try:
        # Check_For_One_File
        if (isfile(responder_files_location)):
            if (responder_files_location.endswith('.log')):
                pass

        # Check_For_Multiple_Files
        elif (isdir(responder_files_location)):
            for responder_file in listdir(responder_files_location):
                if (responder_file.endswith('.log')):
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
