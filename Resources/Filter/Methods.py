#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

class Filter:
    def SSH_Nmap_New(nmap_file. location, Dict_System = {}, Dict_SSH_Results = {'kex_algorithms': [], 'server_host_key_algorithms': [], 'encryption_algorithms': [], 'mac_algorithms': []}):
        with open(nmap_file, 'r') as f:
            Report = f.read().splitlines()

        for Result in range(1, len(Report)-1):
            if ("Nmap scan report" in Report[Result]): IP_Address = Report[Result].split(" ")[4]
            elif ("Host is" not in Report[Result] and "Scanned" not in Report[Result] and "PORT" not in Report[Result] and "MAC Address" not in Report[Result] and not "syn-ack" in Report[Result] and not "|" in Report[Result] and not "#" in Report[Result] and not "Read data" in Report[Result] and not "" in Report[Result]): pass
            elif ("tcp" in Report[Result]): Port = Report[Result].split('/')[0]
            elif ("|" in Report[Result]):
                if ("kex_algorithms" in Report[Result][4:] or "server_host_key_algorithms" in Report[Result][4:] or "encryption_algorithms" in Report[Result][4:] or "mac_algorithms" in Report[Result][4:]):
                    Dict_System[f'{IP_Address}:{Port}'] = ""
                    Target = Report[Result][4:].split(" ")[0]
                    while True:
                        Result += 1
                        if ("server_host_key_algorithms" not in Report[Result] and "encryption_algorithms" not in Report[Result] and "mac_algorithms" not in Report[Result] and "compression_algorithms" not in Report[Result]):
                            if (Report[Result][8:] not in Array_SSH_Algorithms):
                                if ('@' in Report[Result][8:]):
                                    if (Report[Result][8:].split("@")[0] not in Array_SSH_Algorithms):
                                        Dict_SSH_Results[Target].append(Report[Result][8:])
                                else:
                                    Dict_SSH_Results[Target].append(Report[Result][8:])
                        else: break
                elif ("compression_algorithms" in Report[Result]):
                    Dict_System[f'{IP_Address}:{Port}'] = Dict_SSH_Results
                    Dict_SSH_Results = {'kex_algorithms': [], 'server_host_key_algorithms': [], 'encryption_algorithms': [], 'mac_algorithms': []}

        with open(join(location, 'Vulns.txt'), 'w') as f:
            f.write("Host;kex_algorithms;server_host_key_algorithms;encryption_algorithms;mac_algorithms\n")
            for i in Dict_System:
                f.write(f'{i};')
                for j in Dict_System[i]:
                    for k in range(0, len(Dict_System[i][j])):
                        if (k != len(Dict_System[i][j])-1): f.write(f'{Dict_System[i][j][k]}, ')
                        else: f.write(f'{Dict_System[i][j][k]}')
                    f.write(f';')
                f.write('\n')

 #   def SSH_Nmap():
 #       with open(existing_nmap_file, 'r') as f:
 #           Report = f.readlines()
#
 #       for Result in range(1, len(Report)):
 #           if ("Nmap scan report" in Report[Result]): IP_Address = Report[Result].split(" ")[4].split('\n')[0]
 #           elif ("Host is" not in Report[Result] and "Scanned" not in Report[Result] and "PORT" not in Report[Result] and "MAC Address" not in Report[Result] and not "syn-ack" in Report[Result] and not "|" in Report[Result] and not "#" in Report[Result] and not "Read data" in Report[Result] and not "" in Report[Result]): pass
 #           elif ("tcp" in Report[Result]): Port = Report[Result].split('/')[0]
 #           elif ("|" in Report[Result]):
 #               if ("kex_algorithms" in Report[Result][4:-1] or "server_host_key_algorithms" in Report[Result][4:-1] or "encryption_algorithms" in Report[Result][4:-1] or "mac_algorithms" in Report[Result][4:-1]):
 #                   Dict_System[f'{IP_Address}:{Port}'] = ""
 #                   Target = Report[Result][4:-1].split(" ")[0][:-1]
 #                   while True:
 #                       Result += 1
 #                       if ("server_host_key_algorithms" not in Report[Result] and "encryption_algorithms" not in Report[Result] and "mac_algorithms" not in Report[Result] and "compression_algorithms" not in Report[Result]):
 #                           if (Report[Result][8:-1] not in Array_SSH_Algorithms):
 #                               if ('@' in Report[Result][8:-1]):
 #                                   if (Report[Result][8:-1].split("@")[0] not in Array_SSH_Algorithms):
 #                                       Dict_SSH_Results[Target].append(Report[Result][8:-1])
 #                               else:
 #                                   Dict_SSH_Results[Target].append(Report[Result][8:-1])
 #                       else: break
 #               elif ("compression_algorithms" in Report[Result]):
 #                   Dict_System[f'{IP_Address}:{Port}'] = Dict_SSH_Results
 #                   Dict_SSH_Results = {'kex_algorithms': [], 'server_host_key_algorithms': [], 'encryption_algorithms': [], 'mac_algorithms': []}
#
 #       with open(join(location, 'Vulns.txt'), 'w') as f:
 #           f.write("Host;kex_algorithms;server_host_key_algorithms;encryption_algorithms;mac_algorithms\n")
 #           for i in Dict_System:
 #               f.write(f'{i};')
 #               for j in Dict_System[i]:
 #                   for k in range(0, len(Dict_System[i][j])):
 #                       if (k != len(Dict_System[i][j])-1): f.write(f'{Dict_System[i][j][k]}, ')
 #                       else: f.write(f'{Dict_System[i][j][k]}')
 #                   f.write(f';')
 #               f.write('\n')
