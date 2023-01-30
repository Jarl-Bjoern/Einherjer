#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from Resources.Header_Files.Variables import *

def Markdown_Table(Dict_Result, location, Array_Files = []):
    if (Dict_Result['Header'] != {}):
        Array_Files.append(join(location, 'result_header.md'))
        with open(join(location, 'result_header.md'), 'w', encoding='UTF-8', newline='') as md_file:
            md_file.write('| URL | DNS | X-FRAME-OPTIONS | X-XSS-PROTECTION | CONTENT-SECURITY-POLICY | STRICT-TRANSPORT-SECURITY | X-CONTENT-TYPE-OPTIONS | REFERRER-POLICY |\n')
            md_file.write('| --- | --- | --------------- | ---------------- | ----------------------- | ------------------------- | ---------------------- | --------------- |\n')
            for Target in Dict_Result['Header']:
                Temp_Word = ""
                Temp_Word += f"| {Target} |"
                for Result_Left, Result_Right in Dict_Result['Header'][Target].items():
                    if ((Result_Left == "X-XSS-PROTECTION") and (Result_Right == "1" or (Result_Right == "1; MODE=BLOCK"))): Result_Right = "FEHLT"
                    elif (Result_Left == "X-CONTENT-TYPE-OPTIONS" and Result_Right != "NOSNIFF"): Result_Right = "FEHLT"
                    elif (Result_Left == "X-FRAME-OPTIONS" and Result_Right != "DENY"): Result_Right = "FEHLT"
                    elif (Result_Left == "DNS" and Result_Right == ""): Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"): Temp_Word += " ✓ |"
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Temp_Word += f' {Result_Right} |'
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Temp_Word += " - |"
                    else: Temp_Word += " X |"
                md_file.write(f'{Temp_Word}\n')
    if (Dict_Result['Information'] != {}):
        Array_Files.append(join(location, 'result_information_disclosure.md'))
        with open(join(location, 'result_information_disclosure.md'), 'w', encoding='UTF-8', newline='') as md_file:
            md_file.write('| URL | DNS | X-POWERED-BY | SERVER |\n')
            md_file.write('| --- | --- | ------------ | ------ |\n')
            for Target in Dict_Result['Header']:
                Temp_Word = ""
                Temp_Word += f"| {Target} |"
                for Result_Left, Result_Right in Dict_Result['Information'][Target].items():
                    if (Result_Left == "DNS" and Result_Right == ""): Result_Right = "FEHLT"
                    elif (Result_Left == Array_Information_Disclosure_Header[0] and Result_Right == ""): Result_Right = "FEHLT"
                    elif (Result_Left == Array_Information_Disclosure_Header[1] and Result_Right == ""): Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"): Temp_Word += f' {Result_Right} |'
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Temp_Word += f' {Result_Right} |'
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Temp_Word += ' - |'
                    else: Temp_Word += ' X |'
                md_file.write(f'{Temp_Word}\n')
    if (Dict_Result['Security_Flag'] != {}):
        Array_Files.append(join(location, 'result_security_flags.md'))
        with open(join(location, 'result_security_flags.md'), 'w', encoding='UTF-8', newline='') as md_file:
            md_file.write('| URL | DNS | HTTPONLY | SAMESITE | SECURITY |\n')
            md_file.write('| --- | --- | -------- | -------- | -------- |\n')
            for Target in Dict_Result['Security_Flag']:
                Temp_Word = ""
                Temp_Word += f"| {Target} |"
                for Result_Left, Result_Right in Dict_Result['Security_Flag'][Target].items():
                    if (Result_Left == "HTTPONLY" and Result_Right != "HTTPONLY"): Result_Right = "FEHLT"
                    elif (Result_Left == "SAMESITE" and Result_Right != "SAMESITE"): Result_Right = "FEHLT"
                    elif (Result_Left == "SECURITY" and Result_Right != "SECURITY"): Result_Right = "FEHLT"
                    elif (Result_Left == "DNS" and Result_Right == ""): Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"): Temp_Word += " ✓ |"
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Temp_Word += f' {Result_Right} |'
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Temp_Word += " - |"
                    else: Temp_Word += " X |"
                md_file.write(f'{Temp_Word}\n')
    if (Dict_Result['Certificate'] != {}):
        Array_Files.append(join(location, 'result_certificate.md'))
        with open(join(location, 'result_certificate.md'), 'w', encoding='UTF-8', newline='') as md_file:
            md_file.write('| URL | DNS | ISSUER | SUBJECT | SIGNATURE_ALGORITHM | CERT_CREATION_DATE | CERT_EOL | DATE_DIFFERENCE | TESTED_DATE |\n')
            md_file.write('| --- | --- | ------ | ------- | ------------------- | ------------------ | -------- | --------------- | ----------- |\n')
            for Target in Dict_Result['Certificate']:
                Temp_Word = ""
                Temp_Word += f"| {Target} |"
                for Result_Left, Result_Right in Dict_Result['Certificate'][Target].items():
                    if (Result_Left == "DNS" and Result_Right == ""):  Result_Right = "FEHLT"
                    elif (Result_Left != "DNS" and Result_Right == ""): Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"): Temp_Word += f' {Result_Right} |'
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Temp_Word += f' {Result_Right} |'
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Temp_Word += " - |"
                    else: Temp_Word += " X |"
                md_file.write(f'{Temp_Word}\n')
    if (Dict_Result['SSH'] != {}):
        pass
        
    return Array_Files
