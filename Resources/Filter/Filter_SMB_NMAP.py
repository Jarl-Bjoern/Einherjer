#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def SMB_Nmap(nmap_files_location, output_location, Dict_System = {}, Dict_SMB_Results = {'smb-security-mode': [], 'smb2-security-mode': [], 'smb-protocols': []}, Array_Temp = []):
    try:
        if (isfile(nmap_files_location)):
            pass
        elif (isdir(nmap_files_location)):
            for nmap_file in listdir(nmap_files_location):
                if (nmap_file.endswith('.nmap')):
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
                        elif ("tcp"           in Report[Result] and
                              "microsoft-ds"  in Report[Result] and
                              "filtered"      not in Report[Result] and
                              "unknown"       not in Report[Result] and
                              "closed"        not in Report[Result]):
                                    Port = Report[Result].split('/')[0]
                        elif ("|" in Report[Result]):
                             if ("smb2-security-mode"         in Report[Result][2:-1] or
                                 "smb-security-mode"          in Report[Result][2:-1]):
                                        Dict_System[f'{IP_Address}:{Port}'] = ""
                                        Target = Report[Result][2:-1].split(" ")[0][:-1]
                                        while True:
                                             Result += 1
                                             if ("smb-protocols"              not in Report[Result] and
                                                 "smb-security-mode"          not in Report[Result] and
                                                 "smb2-security-mode"         not in Report[Result] and
                                                 "MAC Address:"               not in Report[Result] and
                                                 "Nmap scan report"           not in Report[Result]):
                                                     if (':' in Report[Result]):
                                                         # SMBv1
                                                         if (Report[Result].count(':') == 1):
                                                             if ('disabled' in Report[Result] and 'message_signing' in Report[Result]):
    #                                                             print (Report[Result])
                                                                 Dict_SMB_Results[Target].append(Report[Result][8:])
                                                         # SMBv2_SMBv3
                                                         elif (Report[Result].count(':') == 3):
                                                             pass
    #                                                         print (Report[Result][4:-2].replace(':', '_'))
                                             else: break
                             elif ("smb-protocols" in Report[Result][2:-1]):
    #                               Dict_System[f'{IP_Address}:{Port}'] = ""
                                   while True:
                                        Result += 1
                                        if ("smb-security-mode"          not in Report[Result] and
                                            "smb2-security-mode"         not in Report[Result] and
                                            "MAC Address:"               not in Report[Result] and
                                            "Nmap scan report"           not in Report[Result]):
    #                                                       Dict_SMB_Results['smb-protocols'].append(Report[Result][6:])
                                                if ("dialects" in Report[Result]):
                                                    Result += 1
                                                else:
                                                    print (Report[Result][6:])
                                        else: break
    
                        elif ("MAC Address:" in Report[Result]):
                               Dict_System[f'{IP_Address}:{Port}'] = Dict_SMB_Results
                               Dict_SMB_Results = {'smb-security-mode': [], 'smb2-security-mode': [], 'smb-protocols': []}
    
                        elif ("Nmap done" in Report[Result+1]):
                              Dict_System[f'{IP_Address}:{Port}'] = Dict_SMB_Results
    
            Array_Temp.append(join(output_location, 'smb-vulns.csv'))
            with open(join(output_location, 'smb-vulns.csv'), 'w') as f:
                 f.write("Host;smb-security-mode;smb2-security-mode;smb-protocols\n")
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
