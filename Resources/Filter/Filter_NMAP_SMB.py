#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def SMB_Nmap(nmap_files_location, output_location, Dict_System = {}, Dict_SMB_Results = {'DNS': "", 'smb-security-mode': [], 'smb2-security-mode': [], 'smb-protocols': []}, Array_Temp = []):
    try:
        # Check_For_One_File
        if (isfile(nmap_files_location)):
            # NMAP_File
            if (nmap_files_location.endswith('.nmap') or nmap_files_location.endswith('.log') or nmap_files_location.endswith('.txt')):
                    with open(nmap_files_location, 'r') as f:
                        Report = f.read().splitlines()

                    for Result in range(1, len(Report)-1):
                        if ("Nmap scan report" in Report[Result]):
                            if ('(' in Report[Result] and ')' in Report[Result]):
                                IP_Address, Dict_SMB_Results['DNS'] = Report[Result].split(" ")[5][1:-1], Report[Result].split(" ")[4]
                            else:
                                IP_Address, Dict_SMB_Results['DNS'] = Report[Result].split(" ")[4], '-'
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
                        elif ("445/tcp"           in Report[Result] and
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
                                            try:
                                                if ("smb-protocols"              not in Report[Result] and
                                                    "smb-security-mode"          not in Report[Result] and
                                                    "smb2-security-mode"         not in Report[Result] and
                                                    "MAC Address:"               not in Report[Result] and
                                                    "Nmap scan report"           not in Report[Result]):
                                                        if (':' in Report[Result]):
                                                              # SMBv1
                                                              if (Report[Result].count(':') == 1):
                                                                  if ('disabled' in Report[Result] and 'message_signing' in Report[Result]):
                                                                      Dict_SMB_Results[Target].append(Report[Result][4:].replace('message_signing','Message signing').replace('(dangerous, but default)',' '))
                                                              # SMBv2_SMBv3
                                                              elif (Report[Result].count(':') == 3):
                                                                   if ("message signing enabled but not required" not in Report[Result+1]):
                                                                        Dict_SMB_Results['smb2-security-mode'].append(f"{Report[Result+1][6:].replace('required','enforced')}")
                                                else: break
                                            except IndexError:
                                                break
                             elif ("smb-protocols" in Report[Result][2:-1]):
                                   Dict_System[f'{IP_Address}:{Port}'] = ""
                                   while True:
                                        Result += 1
                                        if ("smb-security-mode"          not in Report[Result] and
                                            "smb2-security-mode"         not in Report[Result] and
                                            "MAC Address:"               not in Report[Result] and
                                            "Nmap scan report"           not in Report[Result]):
                                                if ("dialects" in Report[Result]):
                                                    Result += 1
                                                elif ("(SMBv1)" in Report[Result]):
                                                    Dict_SMB_Results['smb-protocols'].append(Report[Result][6:24])
                                                elif ("_" in Report[Result]):
                                                    Dict_SMB_Results['smb-protocols'].append(Report[Result][6:].replace(':', '_'))
                                                    break
                                                else:
                                                    Dict_SMB_Results['smb-protocols'].append(Report[Result][6:].replace(':', '_'))
                                        else: break

                        elif ("MAC Address:"     in Report[Result]   or
                              "Nmap done"        in Report[Result+1] or
                              "Nmap scan report" in Report[Result+1]):
                                   try:
                                        Temp_Dict = Dict_SMB_Results
                                        if (Temp_Dict != {'DNS':"", 'smb-security-mode': [], 'smb2-security-mode': [], 'smb-protocols': []}):
                                            Dict_System[f'{IP_Address}:{Port}'] = Dict_SMB_Results
                                   except UnboundLocalError: pass
                                   Dict_SMB_Results = {'DNS':"", 'smb-security-mode': [], 'smb2-security-mode': [], 'smb-protocols': []}


            # XML-File
            elif (nmap_files_location.endswith('.xml')):
                pass

        # Looking_For_Multiple_Files
        elif (isdir(nmap_files_location)):
            for nmap_file in listdir(nmap_files_location):
                if (nmap_file.endswith('.nmap')):
                    with open(join(nmap_files_location, nmap_file), 'r') as f:
                        Report = f.read().splitlines()

                    for Result in range(1, len(Report)-1):
                        if ("Nmap scan report" in Report[Result]):
                            if ('(' in Report[Result] and ')' in Report[Result]):
                                IP_Address, Dict_SMB_Results['DNS'] = Report[Result].split(" ")[5][1:-1], Report[Result].split(" ")[4]
                            else:
                                IP_Address, Dict_SMB_Results['DNS'] = Report[Result].split(" ")[4], '-'
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
                        elif ("445/tcp"           in Report[Result] and
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
                                            try:
                                                if ("smb-protocols"              not in Report[Result] and
                                                    "smb-security-mode"          not in Report[Result] and
                                                    "smb2-security-mode"         not in Report[Result] and
                                                    "MAC Address:"               not in Report[Result] and
                                                    "Nmap scan report"           not in Report[Result]):
                                                        if (':' in Report[Result]):
                                                              # SMBv1
                                                              if (Report[Result].count(':') == 1):
                                                                  if ('disabled' in Report[Result] and 'message_signing' in Report[Result]):
                                                                      Dict_SMB_Results[Target].append(Report[Result][4:].replace('message_signing','Message signing').replace('(dangerous, but default)',' '))
                                                              # SMBv2_SMBv3
                                                              elif (Report[Result].count(':') == 3):
                                                                   if ("message signing enabled but not required" not in Report[Result+1]):
                                                                        Dict_SMB_Results['smb2-security-mode'].append(f"{Report[Result+1][6:].replace('required','enforced')}")
                                                else: break
                                            except IndexError:
                                                break
                             elif ("smb-protocols" in Report[Result][2:-1]):
                                   Dict_System[f'{IP_Address}:{Port}'] = ""
                                   while True:
                                        Result += 1
                                        if ("smb-security-mode"          not in Report[Result] and
                                            "smb2-security-mode"         not in Report[Result] and
                                            "MAC Address:"               not in Report[Result] and
                                            "Nmap scan report"           not in Report[Result]):
                                                if ("dialects" in Report[Result]):
                                                    Result += 1
                                                elif ("(SMBv1)" in Report[Result]):
                                                    Dict_SMB_Results['smb-protocols'].append(Report[Result][6:24])
                                                elif ("_" in Report[Result]):
                                                    Dict_SMB_Results['smb-protocols'].append(Report[Result][6:].replace(':', '_'))
                                                    break
                                                else:
                                                    Dict_SMB_Results['smb-protocols'].append(Report[Result][6:].replace(':', '_'))
                                        else: break

                        elif ("MAC Address:"     in Report[Result]   or
                              "Nmap done"        in Report[Result+1] or
                              "Nmap scan report" in Report[Result+1]):
                                   try:
                                        Temp_Dict = Dict_SMB_Results
                                        if (Temp_Dict != {'DNS':"", 'smb-security-mode': [], 'smb2-security-mode': [], 'smb-protocols': []}):
                                            Dict_System[f'{IP_Address}:{Port}'] = Dict_SMB_Results
                                   except UnboundLocalError: pass
                                   Dict_SMB_Results = {'DNS':"", 'smb-security-mode': [], 'smb2-security-mode': [], 'smb-protocols': []}

        # Write_Output
        Array_Temp.append(join(output_location, 'smb-vulns.csv'))
        with open(join(output_location, 'smb-vulns-temp.csv'), 'w') as f:
            f.write("Host;DNS;smb-security-mode;smb2-security-mode;smb-protocols\n")
            for i in Dict_System:
                f.write(f'{i};')
                for j in Dict_System[i]:
                    if (type(Dict_System[i][j]) == str):
                        if (Dict_System[i][j] == ""):
                            f.write('-')
                        else:
                            f.write(f'{Dict_System[i][j]}')
                    else:
                        for k in range(0, len(Dict_System[i][j])):
                            if (k != len(Dict_System[i][j])-1): f.write(f'{Dict_System[i][j][k]}, ')
                            else: f.write(f'{Dict_System[i][j][k]}')
                    f.write(f';')
                f.write('\n')

        # Check_Output_For_Empty_Fields
        with open(join(output_location, 'smb-vulns.csv'), 'w') as fw:
            with open(join(output_location, 'smb-vulns-temp.csv'), 'r') as f:
                for _ in f.read().splitlines():
                    if (';;;;' not in _):
                        fw.write(f'{_}\n')

        remove(join(output_location, 'smb-vulns-temp.csv'))
    except FileNotFoundError:
        pass

    return Array_Temp
