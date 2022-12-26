#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from Resources.VF import *

def Markdown_Table(Dict_Result, location, Array_Files = []):
    if (Dict_Result['Header'] != {}):
        Array_Files.append(join(location, 'result_header.md'))
        with open(join(location, 'result_header.md'), 'w', encoding='UTF-8', newline='') as md_file:
            md_file.write('| URL | DNS | X-FRAME-OPTIONS | X-XSS-PROTECTION | CONTENT-SECURITY-POLICY | STRICT-TRANSPORT-SECURITY | X-CONTENT-TYPE-OPTIONS | REFERRER-POLICY |')
            md_file.write('| --- | --- | --------------- | ---------------- | ----------------------- | ------------------------- | ---------------------- | --------------- |')
            for Target in Dict_Result['Header']:
                Temp_Word = ""
                for Result_Left, Result_Right in Dict_Result['Header'][Target].items():
                    if ((Result_Left == "X-XSS-PROTECTION") and (Result_Right == "1" or (Result_Right == "1; MODE=BLOCK"))): Result_Right = "FEHLT"
                    elif (Result_Left == "X-CONTENT-TYPE-OPTIONS" and Result_Right != "NOSNIFF"): Result_Right = "FEHLT"
                    elif (Result_Left == "X-FRAME-OPTIONS" and Result_Right != "DENY"): Result_Right = "FEHLT"
                    elif (Result_Left == "DNS" and Result_Right == ""): Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"): Temp_Word += "| ✓ | "
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Temp_Word += f'| {Result_Right} | '
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Temp_Word += "| - | "
                    else: Temp_Word += "| X | "
                md_file.write(f'{Temp_Word}\n')
    if (Dict_Result['Information'] != {}):
        Array_Files.append(join(location, 'result_information_disclosure.md'))
        with open(join(location, 'result_information_disclosure.md'), 'w', encoding='UTF-8', newline='') as md_file:
            md_file.write('| URL | DNS | X-POWERED-BY | SERVER |')
            md_file.write('| --- | --- | ------------ | ------ |')
            for Target in Dict_Result['Header']:
                Temp_Word = ""
                for Result_Left, Result_Right in Dict_Result['Information'][Target].items():
                    if (Result_Left == "DNS" and Result_Right == ""): Result_Right = "FEHLT"
                    elif (Result_Left == Array_Information_Disclosure_Header[0] and Result_Right == ""): Result_Right = "FEHLT"
                    elif (Result_Left == Array_Information_Disclosure_Header[1] and Result_Right == ""): Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"): Temp_Word += f'| {Result_Right} | '
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Temp_Word += f'| {Result_Right} | '
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Temp_Word += '| - | '
                    else: Temp_Word += '| X | '
                md_file.write(f'{Temp_Word}\n')
    if (Dict_Result['Security_Flag'] != {}):
        pass
    if (Dict_Result['SSH'] != {}):
        pass
        
    return Array_Files
