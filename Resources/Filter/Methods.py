#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

class Filter:
    def Hostname_Filter(Template_File, Input_File, Output_Location, Template_Array = [], Target_Array = [], Dict_DNS = {}, Array_Temp = []):
        try:
            def Read_File_Template(File_Name):
                with open(File_Name) as f:
                    return f.read().splitlines()

            Target_Array = Read_File_Template(Input_File)
            for _ in Read_File_Template(Template_File):
                if (':' in _):   x = _.split(':')
                elif ('=' in _): x = _.split('=')
                Dict_DNS[str(x[0])] = str(x[1])

            with open(join(Output_Location, 'hostnames.txt'), 'w') as f:
                with open(join(Output_Location, 'affected_systems.txt'), 'w') as af:
                    for _ in Target_Array:
                        for Target_DNS in Dict_DNS:
                            if (Target_DNS in _):
                                print (Dict_DNS[Target_DNS])
                                f.write(f'{Dict_DNS[Target_DNS]}\n')
                                af.write(f'{_} ({Dict_DNS[Target_DNS]})\n')
                                break
                        else:
                            f.write('-\n')
                            af.write(f'{_} (-)')
            Array_Temp.append(join(Output_Location, 'hostnames.txt')), Array_Temp.append(join(Output_Location, 'affected_systems.txt'))
        except FileNotFoundError:
            pass

        return Array_Temp

    def Screenshot_Frame(Screen_Dir, Screenshot_Thickness, Array_Temp = []):
        for Picture in listdir(Screen_Dir):
            raw_image = imread(join(Screen_Dir, Picture))
            height    = raw_image.shape[0]
            width     = raw_image.shape[1]
            start_point, end_point = (0,0), (width, height)
            color     = (0,0,0)
            img       = rectangle(raw_image, start_point, end_point, color, int(Screenshot_Thickness))
            imwrite(join(Screen_Dir, Picture), img)
            Array_Temp.append(join(Screen_Dir, Picture))

        return Array_Temp

    def SSH_Nmap(nmap_files_location, output_location, Dict_System = {}, Dict_SSH_Results = {'kex_algorithms': [], 'server_host_key_algorithms': [], 'encryption_algorithms': [], 'mac_algorithms': [], 'auth_methods': []}, Array_Temp = []):
        for nmap_file in listdir(nmap_files_location):
            if (nmap_file.endswith('.nmap')):
                with open(join(nmap_files_location, nmap_file), 'r') as f:
                    Report = f.read().splitlines()

                for Result in range(1, len(Report)-1):
                    if ("Nmap scan report" in Report[Result]): IP_Address = Report[Result].split(" ")[4]
                    elif ("Host is" not in Report[Result] and
                          "Scanned" not in Report[Result] and
                          "PORT" not in Report[Result] and
                          "MAC Address" not in Report[Result] and
                          not "syn-ack" in Report[Result] and
                          not "|" in Report[Result] and
                          not "#" in Report[Result] and
                          not "Read data" in Report[Result] and
                          not "" in Report[Result]):
                                pass
                    elif ("tcp" in Report[Result]): Port = Report[Result].split('/')[0]
                    elif ("|" in Report[Result]):
                         if ("kex_algorithms" in Report[Result][4:-1] or
                             "server_host_key_algorithms" in Report[Result][4:-1] or
                             "encryption_algorithms" in Report[Result][4:-1] or
                             "mac_algorithms" in Report[Result][4:-1]):
                                    Dict_System[f'{IP_Address}:{Port}'] = ""
                                    Target = Report[Result][4:-1].split(" ")[0][:-1]
                                    while True:
                                         Result += 1
                                         if ("server_host_key_algorithms" not in Report[Result] and
                                             "encryption_algorithms" not in Report[Result] and
                                             "mac_algorithms" not in Report[Result] and
                                             "compression_algorithms" not in Report[Result]):
                                                  if ('@' in Report[Result][8:]):
                                                       if (Report[Result][8:].split("@")[0] not in Array_SSH_Algorithms):
                                                           Dict_SSH_Results[Target].append(Report[Result][8:])
                                                  else:
                                                       if (Report[Result][8:] not in Array_SSH_Algorithms):
                                                            Dict_SSH_Results[Target].append(Report[Result][8:])
                                         else: break
                         elif ("Supported authentication methods" in Report[Result][4:-1]):
                               Dict_System[f'{IP_Address}:{Port}'] = ""
                               while True:
                                    Result += 1
                                    if ("ssh2-enum-algos" not in Report[Result] and
                                        "server_host_key_algorithms" not in Report[Result] and
                                        "encryption_algorithms" not in Report[Result] and
                                        "mac_algorithms" not in Report[Result] and
                                        "compression_algorithms" not in Report[Result] and
                                        "MAC Address:" not in Report[Result] and
                                        "|" in Report[Result]):
                                                   if ("publickey" not in Report[Result]):
                                                       Dict_SSH_Results['auth_methods'].append(Report[Result][6:])
                                    else: break
                    elif ("MAC Address:" in Report[Result]):
                           Dict_System[f'{IP_Address}:{Port}'] = Dict_SSH_Results
                           Dict_SSH_Results = {'kex_algorithms': [], 'server_host_key_algorithms': [], 'encryption_algorithms': [], 'mac_algorithms': [], 'auth_methods': []}

        Array_Temp.append(join(output_location, 'ssh-vulns.csv'))
        with open(join(output_location, 'ssh-vulns.csv'), 'w') as f:
             f.write("Host;kex_algorithms;server_host_key_algorithms;encryption_algorithms;mac_algorithms;auth_methods\n")
             for i in Dict_System:
                 f.write(f'{i};')
                 for j in Dict_System[i]:
                     for k in range(0, len(Dict_System[i][j])):
                         if (k != len(Dict_System[i][j])-1): f.write(f'{Dict_System[i][j][k]}, ')
                         else: f.write(f'{Dict_System[i][j][k]}')
                     f.write(f';')
                 f.write('\n')

        return Array_Temp
