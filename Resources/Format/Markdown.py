#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def Markdown_Table(Dict_Result, location, Write_Mode = "", Write_Second_Mode = ""):
    def Write_Extend(File_Name):
        if (exists(File_Name)):  return 'a'
        else:                    return 'w'

    if (Dict_Result['Header'] != {}):
        # Check_For_Existing_File
        Write_Mode = Write_Extend(join(location, 'result_header.md'))

        # Filter_Mode
        with open(join(location, 'result_header.md'), Write_Mode, encoding='UTF-8', newline='') as md_file:
            if (Write_Mode == 'w'):
                md_file.write('| URL | DNS | X-FRAME-OPTIONS | X-XSS-PROTECTION | CONTENT-SECURITY-POLICY | STRICT-TRANSPORT-SECURITY | X-CONTENT-TYPE-OPTIONS | REFERRER-POLICY |\n')
                md_file.write('| --- | --- | --------------- | ---------------- | ----------------------- | ------------------------- | ---------------------- | --------------- |\n')

            for Target in Dict_Result['Header']:
                Temp_Word = ""
                Temp_Word += f"| {Target} |"
                for Result_Left, Result_Right in Dict_Result['Header'][Target].items():
                    if (Result_Left == "DNS" and Result_Right == ""):        Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"):   Temp_Word += " ✓ |"
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Temp_Word += f' {Result_Right} |'
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Temp_Word += " - |"
                    else: Temp_Word += " X |"
                md_file.write(f'{Temp_Word}\n')

    if (Dict_Result['Information'] != {}):
        # Check_For_Existing_File
        Write_Mode = Write_Extend(join(location, 'result_information_disclosure.md'))

        # Filter_Mode
        with open(join(location, 'result_information_disclosure.md'), Write_Mode, encoding='UTF-8', newline='') as md_file:
            if (Write_Mode == 'w'):
                md_file.write('| URL | DNS | X-POWERED-BY | SERVER |\n')
                md_file.write('| --- | --- | ------------ | ------ |\n')

            for Target in Dict_Result['Header']:
                Temp_Word = ""
                Temp_Word += f"| {Target} |"
                for Result_Left, Result_Right in Dict_Result['Information'][Target].items():
                    if (Result_Left == "DNS" and Result_Right == ""):        Result_Right = "FEHLT"
                    elif (Result_Left in Array_Information_Disclosure_Header and Result_Right == ""): Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"):   Temp_Word += f' {Result_Right} |'
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Temp_Word += f' {Result_Right} |'
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Temp_Word += ' - |'
                    else: Temp_Word += ' X |'
                md_file.write(f'{Temp_Word}\n')

    if (Dict_Result['Security_Flag'] != {}):
        # Check_For_Existing_File
        Write_Mode = Write_Extend(join(location, 'result_security_flags.md'))

        # Filter_Mode
        with open(join(location, 'result_security_flags.md'), Write_Mode, encoding='UTF-8', newline='') as md_file:
            if (Write_Mode == 'w'):
                md_file.write('| URL | DNS | HTTPONLY | SAMESITE | SECURITY |\n')
                md_file.write('| --- | --- | -------- | -------- | -------- |\n')

            for Target in Dict_Result['Security_Flag']:
                Temp_Word = ""
                Temp_Word += f"| {Target} |"
                for Result_Left, Result_Right in Dict_Result['Security_Flag'][Target].items():
                    if (Result_Left == "HTTPONLY" and Result_Right != "HTTPONLY"):   Result_Right = "FEHLT"
                    elif (Result_Left == "SAMESITE" and Result_Right != "SAMESITE"): Result_Right = "FEHLT"
                    elif (Result_Left == "SECURITY" and Result_Right != "SECURITY"): Result_Right = "FEHLT"
                    elif (Result_Left == "DNS" and Result_Right == ""):              Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"):   Temp_Word += " ✓ |"
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Temp_Word += f' {Result_Right} |'
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Temp_Word += " - |"
                    else:                                                    Temp_Word += " X |"
                md_file.write(f'{Temp_Word}\n')

    if (Dict_Result['Certificate'] != {}):
        # Check_For_Existing_File
        Write_Mode = Write_Extend(join(location, 'result_certificate.md'))

        # Filter_Mode
        with open(join(location, 'result_certificate.md'), Write_Mode, encoding='UTF-8', newline='') as md_file:
            if (Write_Mode == 'w'):
                md_file.write('| URL | DNS | ISSUER | SUBJECT | SIGNATURE_ALGORITHM | PUBLIC_KEY | CERT_CREATION_DATE | CERT_EOL | DATE_DIFFERENCE | TESTED_DATE |\n')
                md_file.write('| --- | --- | ------ | ------- | ------------------- | ---------- | ------------------ | -------- | --------------- | ----------- |\n')

            for Target in Dict_Result['Certificate']:
                Temp_Word = ""
                Temp_Word += f"| {Target} |"
                for Result_Left, Result_Right in Dict_Result['Certificate'][Target].items():
                    if (Result_Left == "DNS" and Result_Right == ""):   Result_Right = "FEHLT"
                    elif (Result_Left != "DNS" and Result_Right == ""): Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"):   Temp_Word += f' {Result_Right} |'
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Temp_Word += f' {Result_Right} |'
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Temp_Word += " - |"
                    else:                                                    Temp_Word += " - |"
                md_file.write(f'{Temp_Word}\n')

    if (Dict_Result['HTTP_Methods'] != {}):
        # Check_For_Existing_File
        Write_Mode = Write_Extend(join(location, 'result_http_methods.md'))

        # Filter_Mode
        with open(join(location, f'result_http_methods.md'), 'w', encoding='UTF-8', newline='') as md_file:
            if (Write_Mode == 'w'):
                md_file.write('| URL | DNS | TRACE |\n')
                md_file.write('| --- | --- | ----- |\n')

            for Target in Dict_Result['HTTP_Methods']:
                Temp_Word = ""
                Temp_Word += f"| {Target} |"
                for Result_Left, Result_Right in Dict_Result['HTTP_Methods'][Target].items():
                    if (Result_Left == "DNS" and Result_Right == ""):        Result_Right = "FEHLT"
                    elif (Result_Left != "DNS" and Result_Right == "FEHLT"): Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"):   Temp_Word += ' X |'
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Temp_Word += f' {Result_Right} |'
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Temp_Word += " - |"
                    else:                                                    Temp_Word += " ✓ |"
                md_file.write(f'{Temp_Word}\n')

    if (Dict_Result['FTP'] != {}):
        # Check_For_Existing_File
        Write_Mode = Write_Extend(join(location, 'result_ftp.md'))

        # Filter_Mode
        with open(join(location, 'result_ftp.md'), Write_Mode, encoding='UTF-8', newline='') as md_file:
            if (Write_Mode == 'w'):
                    md_file.write('| URL | DNS | BANNER | ANONYMOUS_LOGIN |\n')
                    md_file.write('| --- | --- | ------ | --------------- |\n')

            for Target in Dict_Result['FTP']:
                Temp_Word = ""
                Temp_Word += f"| {Target} |"
                for Result_Left, Result_Right in Dict_Result['FTP'][Target].items():
                    if (Result_Left == "DNS" and Result_Right == ""):        Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "False"):
                        if (Result_Left == "Anonymous_Login"): Temp_Word += " X |"
                        else:                                  Temp_Word += f" {Result_Right} |"
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Temp_Word += f" {Result_Right} |"
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Temp_Word += " - |"
                    elif (Result_Left != "DNS" and Result_Right == "False"):
                        if (Result_Left == "Anonymous_Login"): Temp_Word += f" ✓ |"
                        else:                                  Temp_Word += f" {Result_Right} |"

                md_file.write(f'{Temp_Word}\n')

    if (Dict_Result['SSL'] != {}):
        # Check_For_Existing_File
        Write_Mode        = Write_Extend(join(location, 'result_ssl_ciphers.md'))
        Write_Second_Mode = Write_Extend(join(location, 'result_ssl_vulns.md'))

        # Filter_Mode
        with open(join(location, f'result_ssl_ciphers.md'), Write_Mode, encoding='UTF-8', newline='') as md_file:
            with open(join(location, f'result_ssl_vulns.md'), Write_Second_Mode, encoding='UTF-8', newline='') as md_sec_file:
                if (Write_Mode == 'w'):
                    md_file.write('| Host | DNS | Protocol | Key_Size | Ciphers | Encryption | Key_Exchange |\n')
                    md_file.write('| ---- | --- | -------- | -------- | ------- | ---------- | ------------ |\n')
                if (Write_Second_Mode == 'w'):
                    md_sec_file.write('| Host | DNS | Vulnerabilities |\n')
                    md_sec_file.write('| ---- | --- | --------------- |\n')                   

                for Target in Dict_Result['SSL']:
                    Temp_Word = ""
                    Temp_Word += f"| {Target} |"
                    for Result_Left, Result_Right in Dict_Result['SSL'][Target].items():
                        if (Result_Left == "DNS" and Result_Right == ""):   Temp_Word += " - |"
                        elif (Result_Left == "DNS" and Result_Right != ""): Temp_Word += f" {Result_Right} |"

                        if (Result_Left == "Ciphers"):
                            for _ in Result_Right:
                                if (_['Protocol'] != "" and _['Ciphers'] != []):
                                    for Cipher in _['Ciphers']:
                                        Temp_Word  += f" {_['Protocol']} | {Cipher['Key_Size']} | {Cipher['Name']} |"
                                        if (Cipher['Curve_Name'] != None and Cipher['Curve_Name'] != ''):
                                            Temp_Word += f" {Cipher['Curve_Name']} |"
                                        else: Temp_Word += " - |"
                                        if (Cipher['Type'] != '' and Cipher['Curve_Size'] != '' and Cipher['Curve_Size'] != None):
                                            Temp_Word += f" {Cipher['Type']}_{Cipher['Curve_Size']} |"
                                        else: Temp_Word += " - |"
                                        md_file.write(f'{Temp_Word}\n')
                        elif (Result_Left == "SSL_Vulns"):
                            for _ in Result_Right:
                                Temp_Word = ""
                                Temp_Word += f"| {Target} |"
                                if (_ == "POODLE" and Result_Right[_] != "False"):
                                    Temp_Word += ' The system is vulnerable for POODLE (CVE-2014-3566) |'
                                elif (_ == "CRIME" and Result_Right[_] != False):
                                    Temp_Word += ' The system is vulnerable for CRIME (CVE-2012-4929) |'
                                elif (_ == "HEARTBLEED" and Result_Right[_] != False):
                                    Temp_Word += ' The system is vulnerable for HEARTBLEED (CVE-2014-0160) |'
                                elif (_ == "CCS_INJECTION" and Result_Right[_] != False):
                                    Temp_Word += ' The system is vulnerable for CCS_INJECTION (CVE-2014-0224) |'
                                elif (_ == "ROBOT" and Result_Right[_] != False):
                                    Temp_Word += ' The system is vulnerable for ROBOT () |'
                                elif (_ == "CLIENT_RENEGOTIATION_DOS" and Result_Right[_] != False):
                                    Temp_Word += ' The system is vulnerable for CLIENT_RENEGOTIATION_DOS () |'
                                elif (_ == "FALLBACK_SCSV" and Result_Right[_] != False):
                                    Temp_Word += ' The system is vulnerable for FALLBACK_SCSV () |'
                                elif (_ == "BREACH" and Result_Right[_] != "False"):
                                    Temp_Word += ' The system is vulnerable for BREACH (CVE-2013-3587) |'
                                elif (_ == "LOGJAM" and Result_Right[_] != False):
                                    Temp_Word += ' The system is vulnerable for LOGJAM (CVE-2015-4000) |'
                                elif (_ == "BEAST" and Result_Right[_] != False):
                                    Temp_Word += ' The system is vulnerable for BEAST () |'
                                elif (_ == "LUCKY13" and Result_Right[_] != False):
                                    Temp_Word += ' The system is vulnerable for LUCKY13 () |'

                                md_file.write(f'{Temp_Word}\n')
                        elif (Result_Left == "Curves"):
                            pass

    if (Dict_Result['SSH'] != {}):
        pass
