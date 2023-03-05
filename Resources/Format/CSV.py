#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def CSV_Table(Dict_Result, location, Array_Files = []):
    try: import csv
    except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")

    if (Dict_Result['Header'] != {}):
        Array_Files.append(join(location, 'result_header.csv'))
        with open(join(location, 'result_header.csv'), 'w', encoding='UTF-8', newline='') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow((['URL','DNS'] + Array_Header))
            for Target in Dict_Result['Header']:
                Array_Temp = []
                Array_Temp.append(Target)
                for Result_Left, Result_Right in Dict_Result['Header'][Target].items():
                    if ((Result_Left == "X-XSS-PROTECTION") and (Result_Right == "1" or (Result_Right == "1; MODE=BLOCK"))): Result_Right = "FEHLT"
                    elif (Result_Left == "X-CONTENT-TYPE-OPTIONS" and Result_Right != "NOSNIFF"): Result_Right = "FEHLT"
                    elif (Result_Left == "X-FRAME-OPTIONS" and Result_Right != "DENY"): Result_Right = "FEHLT"
                    elif (Result_Left == "DNS" and Result_Right == ""): Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"): Array_Temp.append("✓")
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Array_Temp.append("-")
                    else: Array_Temp.append("X")
                writer.writerow(Array_Temp)
    if (Dict_Result['Information'] != {}):
        Array_Files.append(join(location, 'result_information_disclosure.csv'))
        with open(join(location, 'result_information_disclosure.csv'), 'w', encoding='UTF-8', newline='') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow((['URL','DNS'] + Array_Information_Disclosure_Header))
            for Target in Dict_Result['Header']:
                Array_Temp = []
                Array_Temp.append(Target)
                for Result_Left, Result_Right in Dict_Result['Information'][Target].items():
                    if (Result_Left == "DNS" and Result_Right == ""): Result_Right = "FEHLT"
                    elif (Result_Left == Array_Information_Disclosure_Header[0] and Result_Right == ""): Result_Right = "FEHLT"
                    elif (Result_Left == Array_Information_Disclosure_Header[1] and Result_Right == ""): Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Array_Temp.append("-")
                    else: Array_Temp.append("X")
                writer.writerow(Array_Temp)
    if (Dict_Result['SSH'] != {}):
        Array_Files.append(join(location, 'result_SSH-Vulns.csv'))
        with open(join(location, 'result_SSH-Vulns.csv'), 'w', encoding='UTF-8', newline='') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow((['Host','DNS'] + Array_SSH_Header))
            for Target in Dict_Result['SSH']:
                Array_Temp = []
                Array_Temp.append(Target)
                for Result_Left, Result_Right in Dict_Result['SSH'][Target].items():
                    for i in range(0, len(Array_SSH_Header)-1):
                        if (Result_Left == "DNS" and Result_Right == ""): 
                            Result_Right = "FEHLT"
                            break
                        elif ((Result_Left == Array_SSH_Header[i] or Result_Left == Array_SSH_Header[i].isupper() or Result_Left == Array_SSH_Header[i].lower()) and Result_Right == ""):
                            Result_Right = "FEHLT"
                            break

                    # Umschreiben, da mehrere Arrays erzeugt werden in Ausgabe
                    if (Result_Left != "DNS" and Result_Right != "FEHLT"): Array_Temp.append("✓")
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Array_Temp.append("-")
                    else: Array_Temp.append("X")
                writer.writerow(Array_Temp)
    if (Dict_Result['Security_Flag'] != {}):
        Array_Files.append(join(location, f'result_security_flags.csv'))
        with open(join(location, f'result_security_flags.csv'), 'w', encoding='UTF-8', newline='') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow((['Host','DNS'] + Array_Security_Flags))
            for Target in Dict_Result['Security_Flag']:
                Array_Temp = []
                Array_Temp.append(Target)
                for Result_Left, Result_Right in Dict_Result['Security_Flag'][Target].items():
                    for i in range(0, len(Array_Security_Flags)-1):
                        if (Result_Left == "DNS" and Result_Right == ""): 
                            Result_Right = "FEHLT"
                            break
                        elif (Result_Left == Array_Security_Flags[i] and Result_Right == ""):
                            Result_Right = "FEHLT"
                            break

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"): Array_Temp.append("✓")
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Array_Temp.append("-")
                    else: Array_Temp.append("X")
                writer.writerow(Array_Temp)
    if (Dict_Result['Certificate'] != {}):
        Array_Files.append(join(location, f'result_certificate.csv'))
        with open(join(location, f'result_certificate.csv'), 'w', encoding='UTF-8', newline='') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(['Host','DNS','Issuer','Subject','Signature_Algorithm','Cert_Creation_Date','Cert_EOL','Date_Difference','Tested_Date'])
            for Target in Dict_Result['Certificate']:
                Array_Temp = []
                Array_Temp.append(Target)
                for Result_Left, Result_Right in Dict_Result['Certificate'][Target].items():
                    if (Result_Left == "DNS" and Result_Right == ""):  Result_Right = "FEHLT"
                    elif (Result_Left != "DNS" and Result_Right == ""): Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Array_Temp.append("-")
                    else: Array_Temp.append("X")
                writer.writerow(Array_Temp)
    if (Dict_Result['HTTP_Methods'] != {}):
        Array_Files.append(join(location, f'result_http_methods.csv'))
        with open(join(location, f'result_http_methods.csv'), 'w', encoding='UTF-8', newline='') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow((['Host','DNS'] + Array_HTTP_Methods))
            for Target in Dict_Result['HTTP_Methods']:
                Array_Temp = []
                Array_Temp.append(Target)
                for Result_Left, Result_Right in Dict_Result['HTTP_Methods'][Target].items():
                    if (Result_Left == "DNS" and Result_Right == ""):  Result_Right = "FEHLT"
                    elif (Result_Left != "DNS" and Result_Right == ""): Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FALSE"): Array_Temp.append("✓")
                    elif (Result_Left == "DNS" and Result_Right != "FALSE"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Array_Temp.append("-")
                    else: Array_Temp.append("X")
                writer.writerow(Array_Temp)           
    if (Dict_Result['SSL'] != {}):
        Array_Files.append(join(location, f'result_ssl_ciphers.csv'))
        with open(join(location, f'result_ssl_ciphers.csv'), 'w', encoding='UTF-8', newline='') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow((['Host','DNS','Protocol','Ciphers','Key_Size','Anonymous','Curve','Curve_Type','Curve_Size']))
            for Target in Dict_Result['SSL']:
                Array_Temp = []
                Array_Temp.append(Target)
                for Result_Left, Result_Right in Dict_Result['SSL'][Target].items():
                    if (Result_Left == "DNS" and Result_Right == ""):  Array_Temp.append("-")
                    elif (Result_Left == "DNS" and Result_Right != ""): Array_Temp.append(Result_Right)

                    if (Result_Left == "Ciphers"):
                        for _ in Result_Right:
                            if (_['Protocol'] != "" and _['Ciphers'] != []):
                                for Cipher in _['Ciphers']:
                                    Temp_Arr = [_['Protocol'],Cipher['Name'],Cipher['Key_Size'],Cipher['Anonymous']]
                                    if (Cipher['Curve_Name'] != None and Cipher['Curve_Name'] != ''):
                                        Temp_Arr.append(Cipher['Curve_Name'])
                                    else: Temp_Arr.append('-')
                                    if (Cipher['Type'] != ''):
                                        Temp_Arr.append(Cipher['Type'])
                                    else: Temp_Arr.append('-')
                                    if (Cipher['Curve_Size'] != '' and Cipher['Curve_Size'] != None):
                                        Temp_Arr.append(Cipher['Curve_Size'])
                                    else: Temp_Arr.append('-')
                                    writer.writerow(Array_Temp + Temp_Arr)
                    elif (Result_Left == "SSL_Vulns"):
                        pass
                    elif (Result_Left == "Curves"):
                        pass
    return Array_Files
