#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer C. B. Herold

# Libraries
try:
    from resources.VF import *
except ImportError:
    from sys import path as syspath
    syspath.append('.')
    from resources.VF import *

def CSV_Table(Dict_Result):
    try: import csv
    except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")
    global Location
    if (Dict_Result['Header'] != None):
        with open(join(Location, f'{File_Name}_header.csv'), 'w', encoding='UTF-8', newline='') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow((['URL','DNS'] + Array_Header))
            for Target in Dict_Result['Header']:
                Array_Temp = []
                Array_Temp.append(Target)
                for Result_Left, Result_Right in Dict_Result['Header'][Target].items():
                    if ((Result_Left == "X-XSS-Protection" or Result_Left == Array_Header[1].lower() or Result_Left == Array_Header[1].isupper()) and (Result_Right == "1" or (Result_Right == "1; mode=block" or Result_Right == "1; mode=BLOCK"))): Result_Right = "FEHLT"
                    elif ((Result_Left == "X-Content-Type-Options" or Result_Left == Array_Header[4].lower() or Result_Left == Array_Header[4].isupper()) and (Result_Right != "nosniff" or Result_Right != "NOSNIFF")): Result_Right = "FEHLT"
                    elif ((Result_Left == "X-Frame-Options" or Result_Left == Array_Header[0].lower() or Result_Left == Array_Header[0].isupper()) and (Result_Right != "DENY" or Result_Right != "deny")): Result_Right = "FEHLT"
                    elif (Result_Left == "DNS" and Result_Right == ""): Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"): Array_Temp.append("✓")
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Array_Temp.append("-")
                    else: Array_Temp.append("X")
                writer.writerow(Array_Temp)
    if (Dict_Result['Information'] != None):
        with open(join(Location, f'{File_Name}_information_disclosure.csv'), 'w', encoding='UTF-8', newline='') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow((['URL','DNS'] + Array_Information_Disclosure_Header))
            for Target in Dict_Result['Header']:
                Array_Temp = []
                Array_Temp.append(Target)
                for Result_Left, Result_Right in Dict_Result['Information'][Target].items():
                    if (Result_Left == "DNS" and Result_Right == ""): Result_Right = "FEHLT"
                    elif ((Result_Left == Array_Information_Disclosure_Header[0] or Result_Left == Array_Information_Disclosure_Header[0].isupper() or Result_Left == Array_Information_Disclosure_Header[0].lower()) and Result_Right == ""): Result_Right = "FEHLT"
                    elif ((Result_Left == Array_Information_Disclosure_Header[1] or Result_Left == Array_Information_Disclosure_Header[1].isupper() or Result_Left == Array_Information_Disclosure_Header[1].lower()) and Result_Right == ""): Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Array_Temp.append("-")
                    else: Array_Temp.append("X")
                writer.writerow(Array_Temp)
    if (Dict_Result['SSH'] != None):
        with open(join(Location, f'{File_Name}_SSH-Vulns.csv'), 'w', encoding='UTF-8', newline='') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow((['Host','DNS'] + Array_SSH_Header))
            for Target in Dict_Result['SSH']:
                Array_Temp = []
                Array_Temp.append(Target)
                for Result_Left, Result_Right in Dict_Result['SSH'][Target].items():
                    try:
                        for i in range(0, len(Array_SSH_Header)):
                            if (Result_Left == "DNS" and Result_Right == ""): 
                                Result_Right = "FEHLT"
                                break
                            elif ((Result_Left == Array_SSH_Header[i] or Result_Left == Array_SSH_Header[i].isupper() or Result_Left == Array_SSH_Header[i].lower()) and Result_Right == ""):
                                Result_Right = "FEHLT"
                                break
                    except IndexError: pass

                    # Umschreiben, da mehrere Arrays erzeugt werden in Ausgabe
                    if (Result_Left != "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Array_Temp.append("-")
                    else: Array_Temp.append("X")
                writer.writerow(Array_Temp)
    ############
    # NEU      #
    ############
    if (Dict_Result['Security_Flag'] != None):
        with open(join(Location, f'{File_Name}_Security_Flags.csv'), 'w', encoding='UTF-8', newline='') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow((['Host','DNS'] + Array_Security_Flags))
            for Target in Dict_Result['Security_Flag']:
                Array_Temp = []
                Array_Temp.append(Target)
                for Result_Left, Result_Right in Dict_Result['Security_Flag'][Target].items():
                    try:
                        for i in range(0, len(Array_Security_Flags)):
                            if (Result_Left == "DNS" and Result_Right == ""): 
                                Result_Right = "FEHLT"
                                break
                            elif ((Result_Left == Array_SSH_Header[i] or Result_Left == Array_SSH_Header[i].isupper() or Result_Left == Array_SSH_Header[i].lower()) and Result_Right == ""):
                                Result_Right = "FEHLT"
                                break
                    except IndexError: pass

                    # Umschreiben, da mehrere Arrays erzeugt werden in Ausgabe
                    if (Result_Left != "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Array_Temp.append("-")
                    else: Array_Temp.append("X")
                writer.writerow(Array_Temp)
