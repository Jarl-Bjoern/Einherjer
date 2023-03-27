#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def CSV_Table(Dict_Result, location, Write_Mode = ""):
    if (Dict_Result['Header'] != {}):
        # Check_For_Existing_File
        if (exists(join(location, 'result_header.csv'))):  Write_Mode = 'a'
        else:                                              Write_Mode = 'w'

        # Filter_Mode
        with open(join(location, 'result_header.csv'), Write_Mode, encoding='UTF-8', newline='') as csv_file:
            writer = csv.writer(csv_file)
            if (Write_Mode == 'w'):
                writer.writerow((['URL','DNS'] + list(Dict_Header)))

            for Target in Dict_Result['Header']:
                Array_Temp = []
                Array_Temp.append(Target)
                for Result_Left, Result_Right in Dict_Result['Header'][Target].items():
                    if (Result_Left == "DNS" and Result_Right == ""):        Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"):   Array_Temp.append("✓")
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Array_Temp.append("-")
                    else: Array_Temp.append("X")
                writer.writerow(Array_Temp)

    if (Dict_Result['Information'] != {}):
        # Check_For_Existing_File
        if (exists(join(location, 'result_information_disclosure.csv'))):  Write_Mode = 'a'
        else:                                                              Write_Mode = 'w'

        # Filter_Mode
        with open(join(location, 'result_information_disclosure.csv'), Write_Mode, encoding='UTF-8', newline='') as csv_file:
            writer = csv.writer(csv_file)
            if (Write_Mode == 'w'):
                writer.writerow((['URL','DNS'] + Array_Information_Disclosure_Header))

            for Target in Dict_Result['Header']:
                Array_Temp = []
                Array_Temp.append(Target)
                for Result_Left, Result_Right in Dict_Result['Information'][Target].items():
                    if (Result_Left == "DNS" and Result_Right == ""): Result_Right = "FEHLT"
                    elif (Result_Left in Array_Information_Disclosure_Header and Result_Right == ""): Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Array_Temp.append("-")
                    else: Array_Temp.append("X")
                writer.writerow(Array_Temp)

    if (Dict_Result['SSH'] != {}):
        # Check_For_Existing_File
        if (exists(join(location, 'result_ssh_vulns.csv'))):  Write_Mode = 'a'
        else:                                                 Write_Mode = 'w'

        # Filter_Mode
        with open(join(location, 'result_ssh_vulns.csv'), Write_Mode, encoding='UTF-8', newline='') as csv_file:
            writer = csv.writer(csv_file)
            if (Write_Mode == 'w'):
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

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"): Array_Temp.append("✓")
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Array_Temp.append("-")
                    else: Array_Temp.append("X")
                writer.writerow(Array_Temp)

    if (Dict_Result['Security_Flag'] != {}):
        # Check_For_Existing_File
        if (exists(join(location, 'result_security_flags.csv'))):  Write_Mode = 'a'
        else:                                                      Write_Mode = 'w'

        with open(join(location, f'result_security_flags.csv'), Write_Mode, encoding='UTF-8', newline='') as csv_file:
            writer = csv.writer(csv_file)
            if (Write_Mode == 'w'):
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
        # Check_For_Existing_File
        if (exists(join(location, 'result_certificate.csv'))):  Write_Mode = 'a'
        else:                                                   Write_Mode = 'w'

        # Filter_Mode
        with open(join(location, f'result_certificate.csv'), Write_Mode, encoding='UTF-8', newline='') as csv_file:
            writer = csv.writer(csv_file)
            if (Write_Mode == 'w'):
                writer.writerow(['Host','DNS','Issuer','Subject','Signature_Algorithm','Public_Key','Cert_Creation_Date','Cert_EOL','Date_Difference','Tested_Date'])

            for Target in Dict_Result['Certificate']:
                Array_Temp = []
                Array_Temp.append(Target)
                for Result_Left, Result_Right in Dict_Result['Certificate'][Target].items():
                    if (Result_Left == "DNS" and Result_Right == ""):  Result_Right = "FEHLT"
                    elif (Result_Left != "DNS" and Result_Right == ""): Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Array_Temp.append("-")
                    else: Array_Temp.append("-")
                writer.writerow(Array_Temp)

    if (Dict_Result['HTTP_Methods'] != {}):
        # Check_For_Existing_File
        if (exists(join(location, 'result_http_methods.csv'))):  Write_Mode = 'a'
        else:                                                    Write_Mode = 'w'

        # Filter_Mode
        with open(join(location, f'result_http_methods.csv'), Write_Mode, encoding='UTF-8', newline='') as csv_file:
            writer = csv.writer(csv_file)
            if (Write_Mode == 'w'):
                writer.writerow((['Host','DNS'] + Array_HTTP_Methods))

            for Target in Dict_Result['HTTP_Methods']:
                Array_Temp = []
                Array_Temp.append(Target)
                for Result_Left, Result_Right in Dict_Result['HTTP_Methods'][Target].items():
                    if (Result_Left == "DNS" and Result_Right == ""):  Result_Right = "FEHLT"
                    elif (Result_Left != "DNS" and Result_Right == "FEHLT"): Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"): Array_Temp.append("✓")
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Array_Temp.append("-")
                    else: Array_Temp.append("X")
                writer.writerow(Array_Temp)

    if (Dict_Result['SSL'] != {}):
        # Check_For_Existing_File
        if (exists(join(location, 'result_ssl_ciphers.csv'))):  Write_Mode = 'a'
        else:                                                   Write_Mode = 'w'

        # Filter_Mode
        with open(join(location, f'result_ssl_ciphers.csv'), Write_Mode, encoding='UTF-8', newline='') as csv_file:
            writer = csv.writer(csv_file)
            if (Write_Mode == 'w'):
                writer.writerow((['Host','DNS','Protocol','Key_Size','Ciphers','Anonymous','Encryption','Key_Exchange']))

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
                                    Temp_Arr = [_['Protocol'],Cipher['Key_Size'],Cipher['Name'],Cipher['Anonymous']]
                                    if (Cipher['Curve_Name'] != None and Cipher['Curve_Name'] != ''):
                                        Temp_Arr.append(Cipher['Curve_Name'])
                                    else: Temp_Arr.append('-')
                                    if (Cipher['Type'] != '' and Cipher['Curve_Size'] != '' and Cipher['Curve_Size'] != None):
                                        Temp_Arr.append(f"{Cipher['Type']}_{Cipher['Curve_Size']}")
                                    else: Temp_Arr.append('-')
                                    writer.writerow(Array_Temp + Temp_Arr)
                    elif (Result_Left == "SSL_Vulns"):
                        for _ in Result_Right:
                            print (_)
                    elif (Result_Left == "Curves"):
                        pass
