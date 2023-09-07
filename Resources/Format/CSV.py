#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def CSV_Table(Dict_Result, location, Write_Mode = "", Write_Second_Mode = ""):
    def Write_Extend(File_Name):
        if (exists(File_Name)):  return 'a'
        else:                    return 'w'

    if (Dict_Result['Header'] != {}):
        # Check_For_Existing_File
        Write_Mode = Write_Extend(join(location, 'result_header.csv'))

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

                if (Array_Temp.count('✓') != len(Dict_Header)):
                    writer.writerow(Array_Temp)
                else:
                    Standard.Remove_From_Filtered_File(join(location, 'affected_header_targets.txt'), Target)
        Standard.Remove_Empty_Filter_File(join(location, 'result_header.csv')), Standard.Remove_Empty_Filter_File(join(location, 'affected_header_targets.txt'))

    if (Dict_Result['Information'] != {}):
        # Check_For_Existing_File
        Write_Mode = Write_Extend(join(location, 'result_information_disclosure.csv'))

        # Filter_Mode
        with open(join(location, 'result_information_disclosure.csv'), Write_Mode, encoding='UTF-8', newline='') as csv_file:
            writer = csv.writer(csv_file)
            if (Write_Mode == 'w'):
                writer.writerow((['URL','DNS'] + Array_Information_Disclosure_Header))

            for Target in Dict_Result['Header']:
                Array_Temp = []
                Array_Temp.append(Target)
                for Result_Left, Result_Right in Dict_Result['Information'][Target].items():
                    if (Result_Left == "DNS" and Result_Right == ""):        Result_Right = "FEHLT"
                    elif (Result_Left in Array_Information_Disclosure_Header and Result_Right == ""): Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"):   Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Array_Temp.append("-")
                    else: Array_Temp.append("X")

                if (Array_Temp.count('X') != len(Array_Information_Disclosure_Header)):
                    writer.writerow(Array_Temp)
                else:
                    Standard.Remove_From_Filtered_File(join(location, 'affected_http_information_disclosure_targets.txt'), Target)
        Standard.Remove_Empty_Filter_File(join(location, 'result_information_disclosure.csv')), Standard.Remove_Empty_Filter_File(join(location, 'affected_http_information_disclosure_targets.txt'))

    if (Dict_Result['SSH'] != {}):
        # Check_For_Existing_File
        Write_Mode = Write_Extend(join(location, 'result_ssh_vulns.csv'))

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

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"):   Array_Temp.append("✓")
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Array_Temp.append("-")
                    else: Array_Temp.append("X")
                writer.writerow(Array_Temp)

    if (Dict_Result['Security_Flag'] != {}):
        # Check_For_Existing_File
        Write_Mode = Write_Extend(join(location, 'result_security_flags.csv'))

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

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"):   Array_Temp.append("✓")
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Array_Temp.append("-")
                    else: Array_Temp.append("X")

                if (Array_Temp.count('✓') != len(Array_Security_Flags)):
                    writer.writerow(Array_Temp)
                else:
                    Standard.Remove_From_Filtered_File(join(location, 'affected_security_flags_targets.txt'), Target)
        Standard.Remove_Empty_Filter_File(join(location, 'result_security_flags.csv')), Standard.Remove_Empty_Filter_File(join(location, 'affected_security_flags_targets.txt'))

    if (Dict_Result['Certificate'] != {}):
        # Check_For_Existing_File
        Write_Mode = Write_Extend(join(location, 'result_certificate.csv'))

        # Filter_Mode
        with open(join(location, f'result_certificate.csv'), Write_Mode, encoding='UTF-8', newline='') as csv_file:
            writer = csv.writer(csv_file)
            if (Write_Mode == 'w'):
                writer.writerow(['Host','DNS','Issuer','Subject','Signature_Algorithm','Public_Key','Cert_Creation_Date','Cert_EOL','Date_Difference','Tested_Date'])

            for Target in Dict_Result['Certificate']:
                Array_Temp = []
                Array_Temp.append(Target)
                for Result_Left, Result_Right in Dict_Result['Certificate'][Target].items():
                    if (Result_Left == "DNS" and Result_Right == ""):        Result_Right = "FEHLT"
                    elif (Result_Left != "DNS" and Result_Right == ""):      Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"):   Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Array_Temp.append("-")
                    else: Array_Temp.append("-")
                writer.writerow(Array_Temp)

    if (Dict_Result['FTP'] != {}):
        # Check_For_Existing_File
        Write_Mode = Write_Extend(join(location, 'result_ftp.csv'))

        # Filter_Mode
        with open(join(location, 'result_ftp.csv'), Write_Mode, encoding='UTF-8', newline='') as csv_file:
            writer = csv.writer(csv_file)
            if (Write_Mode == 'w'):
                writer.writerow((['URL','DNS','BANNER','ANONYMOUS_LOGIN']))

            for Target in Dict_Result['FTP']:
                Array_Temp = []
                Array_Temp.append(Target)
                for Result_Left, Result_Right in Dict_Result['FTP'][Target].items():
                    if (Result_Left == "DNS" and Result_Right == ""):        Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "False"):
                        if (Result_Left == "Anonymous_Login"): Array_Temp.append("X")
                        else:                                  Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Array_Temp.append("-")
                    elif (Result_Left != "DNS" and Result_Right == "False"):
                        if (Result_Left == "Anonymous_Login"): Array_Temp.append("✓")
                        else:                                  Array_Temp.append(Result_Right)
                writer.writerow(Array_Temp)

    if (Dict_Result['HTTP_Methods'] != {}):
        # Check_For_Existing_File
        Write_Mode = Write_Extend(join(location, 'result_http_methods.csv'))

        # Filter_Mode
        with open(join(location, f'result_http_methods.csv'), Write_Mode, encoding='UTF-8', newline='') as csv_file:
            writer = csv.writer(csv_file)
            if (Write_Mode == 'w'):
                writer.writerow((['Host','DNS'] + Array_HTTP_Methods))

            for Target in Dict_Result['HTTP_Methods']:
                Array_Temp = []
                Array_Temp.append(Target)
                for Result_Left, Result_Right in Dict_Result['HTTP_Methods'][Target].items():
                    if (Result_Left == "DNS" and Result_Right == ""):        Result_Right = "FEHLT"
                    elif (Result_Left != "DNS" and Result_Right == ""):      Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right == "FEHLT"):   Array_Temp.append("✓")
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Array_Temp.append("-")
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left != "DNS" and Result_Right != "FEHLT"): Array_Temp.append("X")

                if (Array_Temp.count('✓') != len(Array_HTTP_Methods)):
                    writer.writerow(Array_Temp)
                else:
                    Standard.Remove_From_Filtered_File(join(location, 'affected_http_methods_targets.txt'), Target)
        Standard.Remove_Empty_Filter_File(join(location, 'result_http_methods.csv')), Standard.Remove_Empty_Filter_File(join(location, 'affected_http_methods_targets.txt'))

    if (Dict_Result['SSL'] != {}):
        # Check_For_Existing_File
        Write_Mode        = Write_Extend(join(location, 'result_ssl_ciphers.csv'))
        Write_Second_Mode = Write_Extend(join(location, 'result_ssl_vulns.csv'))

        # Filter_Mode
        with open(join(location, f'result_ssl_ciphers.csv'), Write_Mode, encoding='UTF-8', newline='') as csv_file:
            with open(join(location, f'result_ssl_vulns.csv'), Write_Second_Mode, encoding='UTF-8', newline='') as csv_sec_file:
                writer     = csv.writer(csv_file)
                writer_Sec = csv.writer(csv_sec_file)
                if (Write_Mode == 'w'):
                    writer.writerow((['Host','DNS','Protocol','Key_Size','Ciphers','Encryption','Key_Exchange']))
                if (Write_Second_Mode == 'w'):
                    writer_Sec.writerow((['Host','DNS','Vulnerabilities']))

                for Target in Dict_Result['SSL']:
                    Array_Temp = []
                    Array_Temp.append(Target)
                    for Result_Left, Result_Right in Dict_Result['SSL'][Target].items():
                        if (Result_Left == "DNS" and Result_Right == ""):   Array_Temp.append("-")
                        elif (Result_Left == "DNS" and Result_Right != ""): Array_Temp.append(Result_Right)

                        if (Result_Left == "Ciphers"):
                            for _ in Result_Right:
                                if (_['Protocol'] != "" and _['Ciphers'] != []):
                                    for Cipher in _['Ciphers']:
                                        Temp_Arr = [_['Protocol'],Cipher['Key_Size'],Cipher['Name']]
                                        if (Cipher['Curve_Name'] != None and Cipher['Curve_Name'] != ''):
                                            Temp_Arr.append(Cipher['Curve_Name'])
                                        else: Temp_Arr.append('-')
                                        if (Cipher['Type'] != '' and Cipher['Curve_Size'] != '' and Cipher['Curve_Size'] != None):
                                            Temp_Arr.append(f"{Cipher['Type']}_{Cipher['Curve_Size']}")
                                        else: Temp_Arr.append('-')
                                        writer.writerow(Array_Temp + Temp_Arr)
                        elif (Result_Left == "SSL_Vulns"):
                            for _ in Result_Right:
                                Temp_Arr = []
                                if (_ == "POODLE" and Result_Right[_] != "False"):
                                    Temp_Arr = ['The system is vulnerable for POODLE (CVE-2014-3566)']
                                elif (_ == "CRIME" and Result_Right[_] != False):
                                    Temp_Arr = ['The system is vulnerable for CRIME (CVE-2012-4929)']
                                elif (_ == "HEARTBLEED" and Result_Right[_] != False):
                                    Temp_Arr = ['The system is vulnerable for HEARTBLEED (CVE-2014-0160)']
                                elif (_ == "CCS_INJECTION" and Result_Right[_] != False):
                                    Temp_Arr = ['The system is vulnerable for CCS_INJECTION (CVE-2014-0224)']
                                elif (_ == "ROBOT" and Result_Right[_] != False):
                                    Temp_Arr = ['The system is vulnerable for ROBOT ()']
                                elif (_ == "CLIENT_RENEGOTIATION_DOS" and Result_Right[_] != False):
                                    Temp_Arr = ['The system is vulnerable for CLIENT_RENEGOTIATION_DOS ()']
                                elif (_ == "FALLBACK_SCSV" and Result_Right[_] != False):
                                    Temp_Arr = ['The system is vulnerable for FALLBACK_SCSV ()']
                                elif (_ == "BREACH" and Result_Right[_] != "False"):
                                    Temp_Arr = ['The system is vulnerable for BREACH (CVE-2013-3587)']
                                elif (_ == "LOGJAM" and Result_Right[_] != False):
                                    Temp_Arr = ['The system is vulnerable for LOGJAM (CVE-2015-4000)']
                                elif (_ == "BEAST" and Result_Right[_] != False):
                                    Temp_Arr = ['The system is vulnerable for BEAST ()']
                                elif (_ == "LUCKY13" and Result_Right[_] != False):
                                    Temp_Arr = ['The system is vulnerable for LUCKY13 ()']

                                if (Temp_Arr != []):
                                    writer_Sec.writerow(Array_Temp + Temp_Arr)
                        elif (Result_Left == "Curves"):
                            pass
