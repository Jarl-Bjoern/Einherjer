#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def NMAP_Unencrypted(nmap_files_location, Dict_System = {}, Array_Filter_Services  = ["access denied", ""], Array_Filter_Protocols = ['ssl','ldaps','https']):
        try:
                # Check_For_One_File
                if (isfile(nmap_files_location)):
                    if (nmap_files_location.endswith('.nmap') or nmap_files_location.endswith('.log')):
                            with open(nmap_files_location, 'r') as f:
                                Report = f.read().splitlines()

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

                Array_Temp.append(join(output_location, 'unencrypted.csv'))
                with open(join(output_location, 'unencrypted.csv'), 'w') as f:
                        f.write("Host;kex_algorithms;server_host_key_algorithms;encryption_algorithms;mac_algorithms;auth_methods\n")
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
