#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from Resources.VF import *

def Markdown_Table(Dict_Result, location, Array_Files = []):
    if (Dict_Result['Header'] != {}):
        Array_Files.append(join(location, 'result_header.md'))
        with open(join(location, 'result_header.md'), 'w', encoding='UTF-8', newline='') as md_file:
            for Target in Dict_Result['Header']:
                md_file.write('| URL | DNS | X-FRAME-OPTIONS | X-XSS-PROTECTION | CONTENT-SECURITY-POLICY | STRICT-TRANSPORT-SECURITY | X-CONTENT-TYPE-OPTIONS | REFERRER-POLICY |')
                md_file.write('| --- | --- | --------------- | ---------------- | ----------------------- | ------------------------- | ---------------------- | --------------- |')
                for Result_Left, Result_Right in Dict_Result['Header'][Target].items():
                    if ((Result_Left == "X-XSS-PROTECTION") and (Result_Right == "1" or (Result_Right == "1; MODE=BLOCK"))): Result_Right = "FEHLT"
                    elif (Result_Left == "X-CONTENT-TYPE-OPTIONS" and Result_Right != "NOSNIFF"): Result_Right = "FEHLT"
                    elif (Result_Left == "X-FRAME-OPTIONS" and Result_Right != "DENY"): Result_Right = "FEHLT"
                    elif (Result_Left == "DNS" and Result_Right == ""): Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"): md_file.write("| ✓ | ")
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): md_file.write(f'| {Result_Right} | ')
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): md_file.write("| - | ")
                    else: md_file.write("| X | ")
                md_file.write('\n')
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
                    elif ((Result_Left == Array_Information_Disclosure_Header[0] or Result_Left == Array_Information_Disclosure_Header[0].isupper() or Result_Left == Array_Information_Disclosure_Header[0].lower()) and Result_Right == ""): Result_Right = "FEHLT"
                    elif ((Result_Left == Array_Information_Disclosure_Header[1] or Result_Left == Array_Information_Disclosure_Header[1].isupper() or Result_Left == Array_Information_Disclosure_Header[1].lower()) and Result_Right == ""): Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Array_Temp.append("-")
                    else: Array_Temp.append("X")
                writer.writerow(Array_Temp)
    if (Dict_Result['Security_Flag'] != {}):
        pass
    if (Dict_Result['SSH'] != {}):
        pass
        
    return Array_Files
