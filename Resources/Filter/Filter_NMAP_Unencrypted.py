#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def NMAP_Unencrypted(file_path, Array_Filter_Services  = ["access denied", ""], Array_Filter_Protocols = ['ssl','ldaps','https']):
        Protocol, Address, Port, Skip_Attributes = "","","",False
        try:
            for event, elem in ET.iterparse(file_path, events=("end",)):
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
