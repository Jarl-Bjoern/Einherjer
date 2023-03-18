#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

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
                    if (Result_Left == "DNS" and Result_Right == ""): Result_Right = "FEHLT"

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
                    elif (Result_Left in Array_Information_Disclosure_Header and Result_Right == ""): Result_Right = "FEHLT"
#                    elif (Result_Left == Array_Information_Disclosure_Header[1] and Result_Right == ""): Result_Right = "FEHLT"

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
                    else: Temp_Word += " - |"
                md_file.write(f'{Temp_Word}\n')

        Array_Files.append(join(location, f'result_http_methods.md'))
        with open(join(location, f'result_http_methods.md'), 'w', encoding='UTF-8', newline='') as md_file:
            md_file.write('| URL | DNS | CONNECT | DELETE | HEAD | OPTIONS | PATCH | POST | PUT | TRACE |\n')
            md_file.write('| --- | --- | ------- | ------ | ---- | ------- | ----- | ---- | --- | ----- |\n')
            for Target in Dict_Result['HTTP_Methods']:
                Temp_Word = ""
                Temp_Word += f"| {Target} |"
                for Result_Left, Result_Right in Dict_Result['HTTP_Methods'][Target].items():
                    if (Result_Left == "DNS" and Result_Right == ""):  Result_Right = "FEHLT"
                    elif (Result_Left != "DNS" and Result_Right == "FEHLT"): Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"): Temp_Word += ' ✓ |'
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Temp_Word += f' {Result_Right} |'
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Temp_Word += " - |"
                    else: Temp_Word += " X |"
                md_file.write(f'{Temp_Word}\n')

    if (Dict_Result['SSL'] != {}):
        Array_Files.append(join(location, f'result_ssl_ciphers.md'))
        with open(join(location, f'result_ssl_ciphers.md'), 'w', encoding='UTF-8', newline='') as md_file:
            md_file.write('| Host | DNS | Protocol | Key_Size | Ciphers | Anonymous | Encryption | Key_Exchange |\n')
            md_file.write('| ---- | --- | -------- | -------- | ------- | --------- | ---------- | ------------ |\n')
            for Target in Dict_Result['SSL']:
                Temp_Word = ""
                Temp_Word += f"| {Target} |"
                for Result_Left, Result_Right in Dict_Result['SSL'][Target].items():
                    if (Result_Left == "DNS" and Result_Right == ""):  Temp_Word += " - |"
                    elif (Result_Left == "DNS" and Result_Right != ""): Temp_Word += f" {Result_Right} |"

                    if (Result_Left == "Ciphers"):
                        for _ in Result_Right:
                            if (_['Protocol'] != "" and _['Ciphers'] != []):
                                for Cipher in _['Ciphers']:
                                    Temp_Word  += f" {_['Protocol']} | {Cipher['Key_Size']} | {Cipher['Name']} | {Cipher['Anonymous']} |"
                                    if (Cipher['Curve_Name'] != None and Cipher['Curve_Name'] != ''):
                                        Temp_Word += f" {Cipher['Curve_Name']} |"
                                    else: Temp_Word += " - |"
                                    if (Cipher['Type'] != '' and Cipher['Curve_Size'] != '' and Cipher['Curve_Size'] != None):
                                        Temp_Word += f" {Cipher['Type']}_{Cipher['Curve_Size']} |"
                                    else: Temp_Word += " - |"
                                    md_file.write(f'{Temp_Word}\n')
                    elif (Result_Left == "SSL_Vulns"):
                        pass
                    elif (Result_Left == "Curves"):
                        pass

    if (Dict_Result['SSH'] != {}):
        pass
        
    return Array_Files
