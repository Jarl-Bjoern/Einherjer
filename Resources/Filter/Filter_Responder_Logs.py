#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def Responder_Logs(responder_files_location, output_location, Dict_System = {}, Array_Temp = [], Array_Output = [], Dict_Temp = {'DNS': "", 'MDNS': "", 'LLMNR': "", 'USER': ""}):
    try:
        # Check_For_One_File
        if (isfile(responder_files_location)):
            if (responder_files_location.endswith('.log') and "Responder-Session" in responder_files_location):
                with open(responder_files_location, 'r') as f:
                    Text = f.read().splitlines()

                for i in Text:
                    if ("Client" in i):
                        Client = i.split(' ')
                    elif ("Username" in i):
                        User = i.split(' ')
                        print (f'{User[8]} - {User[4][1:-1]} - {User[5]} - {Client[10]}')
                    elif ("MDNS" in i):
                        Target = i.split(' ')
                        #if (Target[10].count('.') > 2):
                        #    print (f"{Target[10]} ({Target[15]})")
                        #elif (Target[10].count(':') > 3):
                        #    print (f"{Target[10]} ({Target[13]})")

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
             f.write("LLMNR;MDNS;USER;COMPROMISED\n")
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
