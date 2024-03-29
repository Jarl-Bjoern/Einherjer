#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def NMAP_Header(nmap_files_location, output_location, Dict_System = {}, Dict_Header_Results = {}, Array_Temp = []):
        try:
                # Check_For_One_File
                if (isfile(nmap_files_location)):
                    if (nmap_files_location.endswith('.nmap') or nmap_files_location.endswith('.log') or nmap_files_location.endswith('.txt')):
                            with open(nmap_files_location, 'r') as f:
                                Report = f.read().splitlines()

                            for Result in range(1, len(Report)-1):
                                if ("Nmap scan report" in Report[Result]):
                                    if ('(' in Report[Result] and ')' in Report[Result]):
                                        IP_Address, Dict_Header_Results['DNS'] = Report[Result].split(" ")[5][1:-1], Report[Result].split(" ")[4]
                                    else:
                                        IP_Address, Dict_Header_Results['DNS'] = Report[Result].split(" ")[4], '-'
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
                                      "http"      in Report[Result] and
                                      "filtered"  not in Report[Result] and
                                      "unknown"   not in Report[Result] and
                                      "closed"    not in Report[Result]):
                                            Port = Report[Result].split('/')[0]
                                elif ("|" in Report[Result]):
                                     if ("http-headers:"             in Report[Result][4:-1]):
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
                                                                       Dict_Header_Results[Target].append(Report[Result][8:])
                                                              else:
                                                                   if (Report[Result][8:] not in Array_SSH_Algorithms):
                                                                        Dict_Header_Results[Target].append(Report[Result][8:])
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
                                                    "unknown"                    not in Report[Result] and
                                                    "|" in Report[Result]):
                                                               if ("publickey" not in Report[Result]):
                                                                   Dict_Header_Results['auth_methods'].append(Report[Result][6:])
                                                else: break
        
                                elif ("MAC Address:"     in Report[Result]   or
                                      "Nmap done"        in Report[Result+1] or
                                      "Nmap scan report" in Report[Result+1]):
                                           try:
                                               Temp_Dict = Dict_SSH_Results
                                               if (Temp_Dict != {'DNS': "", 'kex_algorithms': [], 'server_host_key_algorithms': [], 'encryption_algorithms': [], 'mac_algorithms': [], 'auth_methods': []}):
                                                   Dict_System[f'{IP_Address}:{Port}'] = Dict_Header_Results
                                           except: pass
                                           Dict_Header_Results = {'DNS': "", 'kex_algorithms': [], 'server_host_key_algorithms': [], 'encryption_algorithms': [], 'mac_algorithms': [], 'auth_methods': []}

                        #############################

                    elif (nmap_files_location.endswith('.xml')):
                        Protocol, Address, Port, Skip_Attributes = "","","",False
                        try:
                            for event, elem in ET.iterparse(nmap_files_location, events=("end",)):
                                if (event == "end"):
                                    if (elem.tag == "address"):
                                        if (Skip_Attributes != True):
                                            if (elem.attrib['addrtype'] == "ipv4"):
                                                Address = elem.attrib['addr']

                                    elif (elem.tag == "state"):
                                        if (elem.attrib['state'] != "open"):
                                            Skip_Attributes = True

                                    elif (elem.tag == "service"):
                                        if (Skip_Attributes != True):
                                            Protocol = elem.attrib['name']

                                            Product, Version, Extra_Info = "","",""
                                            try:             Product    = elem.attrib['product']
                                            except KeyError: pass
                                            try:             Version    = elem.attrib['version']
                                            except KeyError: pass
                                            try:             Extra_Info = elem.attrib['extrainfo']
                                            except KeyError: pass

                                            Word = ""
                                            if (Product    != ""): Word += f"{Product} "
                                            if (Version    != ""): Word += f"{Version} "
                                            if (Extra_Info != ""): Word += f"{Extra_Info}"

                                    elif (elem.tag == 'script'):
                                        print (elem.attrib['output'])

                                    elif (elem.tag == 'port'):
                                        Port = elem.attrib['portid']

                                        if (Protocol != "" and Address != "" and Port != ""):
                                           if (Protocol not in Array_Filter_Protocols):
                                               print (f'{Address} {Protocol} open {Word}')

                                        Skip_Attributes = False

                        except ET.ParseError:
                            pass #print ("It's seems that the xml file"+Colors.RED+f" {file_path} "+Colors.RESET+"is empty."), exit()

                # Check_For_Multiple_Files
                elif (isdir(nmap_files_location)):
                        pass

                # Write_Output
                Array_Temp.append(join(output_location, 'result-header.csv'))
                with open(join(output_location, 'result-header-temp.csv'), 'w') as f:
                    f.write("Host;DNS;kex_algorithms;server_host_key_algorithms;encryption_algorithms;mac_algorithms;auth_methods\n")
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
                with open(join(output_location, 'result-header.csv'), 'w') as fw:
                    with open(join(output_location, 'result-header-temp.csv'), 'r') as f:
                        for _ in f.read().splitlines():
                            if (';;;;;;' not in _):
                                fw.write(f'{_}\n')
        
                remove(join(output_location, 'result-header-temp.csv'))
        except FileNotFoundError:
                pass

        return Array_Temp
