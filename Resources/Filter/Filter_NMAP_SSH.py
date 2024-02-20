#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def SSH_Nmap(nmap_files_location, output_location, Dict_System = {}, Dict_SSH_Results = {'DNS': "", 'encryption_algorithms': [], 'kex_algorithms': [], 'mac_algorithms': [], 'server_host_key_algorithms': [], 'auth_methods': [], 'sshv1': []}, Array_Temp = []):
    try:
        # Check_For_One_File
        if (isfile(nmap_files_location)):
            if (nmap_files_location.endswith('.nmap') or nmap_files_location.endswith('.log') or nmap_files_location.endswith('.txt')):
                    with open(nmap_files_location, 'r') as f:
                        Report = f.read().splitlines()

                    for Result in range(1, len(Report)-1):
                        if ("Nmap scan report" in Report[Result]):
                            if ('(' in Report[Result] and ')' in Report[Result]):
                                IP_Address, Dict_SSH_Results['DNS'] = Report[Result].split(" ")[5][1:-1], Report[Result].split(" ")[4]
                            else:
                                IP_Address, Dict_SSH_Results['DNS'] = Report[Result].split(" ")[4], '-'
                        elif ("Host is"     not in Report[Result] and
                              "Scanned"     not in Report[Result] and
                              "PORT"        not in Report[Result] and
                              "MAC Address" not in Report[Result] and
                              "syn-ack"     not in Report[Result] and
                              "|"           not in Report[Result] and
                              "#"           not in Report[Result] and
                              "Read data"   not in Report[Result] and
                              "filtered"    not in Report[Result] and
                              "closed"      not in Report[Result] and
                              "unknown"     not in Report[Result] and
                              ""            not in Report[Result]):
                                    pass
                        elif ("tcp"       in Report[Result] and
                              "ssh"       in Report[Result] and
                              "filtered"  not in Report[Result] and
                              "unknown"   not in Report[Result] and
                              "closed"    not in Report[Result]):
                                    Port = Report[Result].split('/')[0]
                        elif ("|" in Report[Result]):
                             if ("kex_algorithms"             in Report[Result][4:-1] or
                                 "server_host_key_algorithms" in Report[Result][4:-1] or
                                 "encryption_algorithms"      in Report[Result][4:-1] or
                                 "mac_algorithms"             in Report[Result][4:-1]):
                                        Dict_System[f'{IP_Address}:{Port}'] = ""
                                        Target = Report[Result][4:-1].split(" ")[0][:-1]
                                        while True:
                                             Result += 1
                                             if ("server_host_key_algorithms" not in Report[Result] and
                                                 "encryption_algorithms"      not in Report[Result] and
                                                 "mac_algorithms"             not in Report[Result] and
                                                 "compression_algorithms"     not in Report[Result] and
                                                 "filtered"                   not in Report[Result] and
                                                 "closed"                     not in Report[Result] and
                                                 "fingerprint-strings"        not in Report[Result] and
                                                 "unknown"                    not in Report[Result]):
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
                                        if ("ssh2-enum-algos"            not in Report[Result] and
                                            "server_host_key_algorithms" not in Report[Result] and
                                            "encryption_algorithms"      not in Report[Result] and
                                            "mac_algorithms"             not in Report[Result] and
                                            "compression_algorithms"     not in Report[Result] and
                                            "MAC Address:"               not in Report[Result] and
                                            "filtered"                   not in Report[Result] and
                                            "closed"                     not in Report[Result] and
                                            "fingerprint-strings"        not in Report[Result] and
                                            "unknown"                    not in Report[Result] and
                                            "|" in Report[Result]):
                                                       if ("publickey" not in Report[Result]):
                                                           Dict_SSH_Results['auth_methods'].append(Report[Result][6:])
                                        else: break

                        elif ("MAC Address:"     in Report[Result]   or
                              "Nmap done"        in Report[Result+1] or
                              "Nmap scan report" in Report[Result+1]):
                                   try:
                                       Temp_Dict = Dict_SSH_Results
                                       if (Temp_Dict != {'DNS': "", 'encryption_algorithms': [], 'kex_algorithms': [], 'mac_algorithms': [], 'server_host_key_algorithms': [], 'auth_methods': [], 'sshv1': []}):
                                           Dict_System[f'{IP_Address}:{Port}'] = Dict_SSH_Results
                                   except: pass
                                   Dict_SSH_Results = {'DNS': "", 'encryption_algorithms': [], 'kex_algorithms': [], 'mac_algorithms': [], 'server_host_key_algorithms': [], 'auth_methods': [], 'sshv1': []}


            elif (nmap_files_location.endswith('.xml')):
                pass


        # Check_For_Multiple_Files
        elif (isdir(nmap_files_location)):
            for nmap_file in listdir(nmap_files_location):
                if (nmap_file.endswith('.nmap') or nmap_files_location.endswith('.txt') or nmap_files_location.endswith('.log')):
                    with open(join(nmap_files_location, nmap_file), 'r') as f:
                        Report = f.read().splitlines()

                    for Result in range(1, len(Report)-1):
                        if ("Nmap scan report" in Report[Result]):
                            IP_Address = Report[Result].split(" ")[4]
                        elif ("Host is"     not in Report[Result] and
                              "Scanned"     not in Report[Result] and
                              "PORT"        not in Report[Result] and
                              "MAC Address" not in Report[Result] and
                              "syn-ack"     not in Report[Result] and
                              "|"           not in Report[Result] and
                              "#"           not in Report[Result] and
                              "Read data"   not in Report[Result] and
                              "filtered"    not in Report[Result] and
                              "closed"      not in Report[Result] and
                              "unknown"     not in Report[Result] and
                              ""            not in Report[Result]):
                                    pass
                        elif ("tcp"       in Report[Result] and
                              "ssh"       in Report[Result] and
                              "filtered"  not in Report[Result] and
                              "unknown"   not in Report[Result] and
                              "closed"    not in Report[Result]):
                                    Port = Report[Result].split('/')[0]
                        elif ("|" in Report[Result]):
                             if ("kex_algorithms"             in Report[Result][4:-1] or
                                 "server_host_key_algorithms" in Report[Result][4:-1] or
                                 "encryption_algorithms"      in Report[Result][4:-1] or
                                 "mac_algorithms"             in Report[Result][4:-1]):
                                        Dict_System[f'{IP_Address}:{Port}'] = ""
                                        Target = Report[Result][4:-1].split(" ")[0][:-1]
                                        while True:
                                             Result += 1
                                             if ("server_host_key_algorithms" not in Report[Result] and
                                                 "encryption_algorithms"      not in Report[Result] and
                                                 "mac_algorithms"             not in Report[Result] and
                                                 "compression_algorithms"     not in Report[Result] and
                                                 "filtered"                   not in Report[Result] and
                                                 "closed"                     not in Report[Result] and
                                                 "unknown"                    not in Report[Result]):
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
                                        if ("ssh2-enum-algos"            not in Report[Result] and
                                            "server_host_key_algorithms" not in Report[Result] and
                                            "encryption_algorithms"      not in Report[Result] and
                                            "mac_algorithms"             not in Report[Result] and
                                            "compression_algorithms"     not in Report[Result] and
                                            "MAC Address:"               not in Report[Result] and
                                            "filtered"                   not in Report[Result] and
                                            "closed"                     not in Report[Result] and
                                            "fingerprint-strings"        not in Report[Result] and
                                            "unknown"                    not in Report[Result] and
                                            "|" in Report[Result]):
                                                       if ("publickey" not in Report[Result]):
                                                           Dict_SSH_Results['auth_methods'].append(Report[Result][6:])
                                        else: break

                        elif ("MAC Address:"     in Report[Result]   or
                              "Nmap done"        in Report[Result+1] or
                              "Nmap scan report" in Report[Result+1]):
                                   try:
                                       Temp_Dict = Dict_SSH_Results
                                       if (Temp_Dict != {'DNS': "", 'encryption_algorithms': [], 'kex_algorithms': [], 'mac_algorithms': [], 'server_host_key_algorithms': [], 'auth_methods': [], 'sshv1': []}):
                                           Dict_System[f'{IP_Address}:{Port}'] = Dict_SSH_Results
                                   except UnboundLocalError: pass
                                   Dict_SSH_Results = {'DNS': "", 'encryption_algorithms': [], 'kex_algorithms': [], 'mac_algorithms': [], 'server_host_key_algorithms': [], 'auth_methods': [], 'sshv1': []}

        # Write_Output
        Array_Temp.append(join(output_location, 'ssh-vulns.csv'))
        with open(join(output_location, 'ssh-vulns-temp.csv'), 'w') as f:
            f.write("Host;DNS;encryption_algorithms;kex_algorithms;mac_algorithms;server_host_key_algorithms;auth_methods;SSH-V1\n")
            for i in Dict_System:
                f.write(f'{i};')
                for j in Dict_System[i]:
                    if (type(Dict_System[i][j]) == str):
                        f.write(f'{Dict_System[i][j]}')
                    else:
                        for k in range(0, len(Dict_System[i][j])):
                            if (k != len(Dict_System[i][j])-1): f.write(f'{Dict_System[i][j][k]}, ')
                            else: f.write(f'{Dict_System[i][j][k]}')
                    f.write(f';')
                f.write('\n')

        # Check_Output_For_Empty_Fields
        with open(join(output_location, 'ssh-vulns.csv'), 'w') as fw:
            with open(join(output_location, 'ssh-vulns-temp.csv'), 'r') as f:
                for _ in f.read().splitlines():
                    if (';;;;;;' not in _ and ';;;;;' not in _):
                        fw.write(f'{_}\n')

        remove(join(output_location, 'ssh-vulns-temp.csv'))
    except FileNotFoundError:
        pass

    return Array_Temp
