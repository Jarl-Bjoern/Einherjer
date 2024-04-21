#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def CSV_Table(Dict_Result, location, language, Write_Mode = "", Write_Second_Mode = ""):
    def Write_Extend(File_Name):
        if (exists(File_Name)):  return 'a'
        else:                    return 'w'

    Dict_Overview_SSL = {}
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
#                writer.writerow(['Host','DNS','Self_Signed','Issuer','Subject','Signature_Algorithm','Public_Key','Cert_Creation_Date','Cert_EOL','Date_Difference','Tested_Date'])
                writer.writerow(['Host','DNS','Issuer','Subject','Signature_Algorithm','Public_Key','Cert_Creation_Date','Cert_EOL','Date_Difference','Tested_Date'])

            for Target in Dict_Result['Certificate']:
                if ('//' in Target):
                    Target_New = Target.split('//')[1]
                else:
                    Target_New = Target

                Array_Temp = []
                Array_Temp.append(Target_New)
                for Result_Left, Result_Right in Dict_Result['Certificate'][Target].items():
                    if (Result_Left == "DNS" and Result_Right == ""):        Result_Right = "FEHLT"
                    elif (Result_Left != "DNS" and Result_Right == ""):      Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"):
                       # if (Result_Left == 'Self_Signed' and Result_Right == True):
                       #     Dict_Overview_SSL[Target_New]['Insecure_Certificate_Signature'] = True
                        if (Result_Left == 'Cert_EOL' and 'expired' in Result_Right):
                            Dict_Overview_SSL[Target_New]['Certificate_Expired'] = True
                        
                        Array_Temp.append(Result_Right)
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


    if (Dict_Result['CORS'] != {}):
        # Check_For_Existing_File
        Write_Mode = Write_Extend(join(location, 'result_cors.csv'))

        # Filter_Mode
        with open(join(location, 'result_cors.csv'), Write_Mode, encoding='UTF-8', newline='') as csv_file:
            writer = csv.writer(csv_file)
            if (Write_Mode == 'w'):
                writer.writerow(['URL','DNS',] + Array_CORS_Header)

            for Target in Dict_Result['CORS']:
                Array_Temp = []
                Array_Temp.append(Target)
                for Result_Left, Result_Right in Dict_Result['CORS'][Target].items():
                    if (Result_Left == "DNS" and Result_Right == ""):        Result_Right = "FEHLT"

                    if (Result_Left != "DNS" and Result_Right != "FEHLT"):   Array_Temp.append("✓")
                    elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Array_Temp.append(Result_Right)
                    elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Array_Temp.append("-")
                    else: Array_Temp.append("X")

                if (Array_Temp.count('✓') != len(Array_CORS_Header)):
                    if (len(Array_Temp) == 3):
                        writer.writerow(Array_Temp)
                else:
                    Standard.Remove_From_Filtered_File(join(location, 'affected_cors_targets.txt'), Target)
        Standard.Remove_Empty_Filter_File(join(location, 'result_cors.csv')), Standard.Remove_Empty_Filter_File(join(location, 'affected_cors_targets.txt'))


    if (Dict_Result['SSL'] != {}):
        # Check_For_Existing_File
        Write_Mode        = Write_Extend(join(location, 'result_ssl_bad_ciphers.csv'))
        Write_Second_Mode = Write_Extend(join(location, 'result_ssl_vulns.csv'))
        Write_Third_Mode  = Write_Extend(join(location, 'result_ssl_good_ciphers.csv'))
        Write_Fourth_Mode = Write_Extend(join(location, 'result_ssl_overview.csv'))

        # Filter_Mode
        with open(join(location, f'result_ssl_bad_ciphers.csv'), Write_Mode, encoding='UTF-8', newline='') as csv_file:
            with open(join(location, f'result_ssl_vulns.csv'), Write_Second_Mode, encoding='UTF-8', newline='') as csv_sec_file:
                with open(join(location, f'result_ssl_good_ciphers.csv'), Write_Third_Mode, encoding='UTF-8', newline='') as csv_third_file:
                    with open(join(location, f'result_ssl_overview.csv'), Write_Fourth_Mode, encoding='UTF-8', newline='') as csv_overview_file:
                        writer          = csv.writer(csv_file)
                        writer_Sec      = csv.writer(csv_sec_file)
                        writer_Third    = csv.writer(csv_third_file)
                        writer_Overview = csv.writer(csv_overview_file)

                        if (Write_Mode == 'w'):
                            writer.writerow((['Host','DNS','Protocol','Key_Size','Ciphers','Encryption','Key_Exchange','Hash_Algorithm']))
                        if (Write_Second_Mode == 'w'):
                            writer_Sec.writerow((['Host','DNS','Vulnerabilities']))
                        if (Write_Third_Mode == 'w'):
                            writer_Third.writerow((['Host','DNS','Protocol','Key_Size','Ciphers','Encryption','Key_Exchange','Hash_Algorithm']))

                        Dict_Overview_SSL = {}
                        for Target in Dict_Result['SSL']:
                            Array_Temp = []
                            Array_Temp.append(Target)
                            for Result_Left, Result_Right in Dict_Result['SSL'][Target].items():
                                if (Result_Left == "DNS" and Result_Right == ""):   Array_Temp.append("-")
                                elif (Result_Left == "DNS" and Result_Right != ""): Array_Temp.append(Result_Right)

                                if (Result_Left == "Ciphers"):
                                    for _ in Result_Right:
                                        if (_['Protocol'] != "" and _['Ciphers'] != []):
                                            if (Target not in Dict_Overview_SSL):
                                                Dict_Overview_SSL[Target] = {
                                                           'DNS': "",
                                'Insecure_Certificate_Signature': False,
                                           'Certificate_Expired': False,
                                                   'DHE <= 1024': False,
                                                    'HEARTBLEED': False,
                                                 'CCS_Injection': False,
                                                         'ROBOT': False,
                                                         'BEAST': False,
                                                         'CRIME': False,
                                                         'DROWN': False,
                                                        'LOGJAM': False,
                                                        'POODLE': False,
                                                       'SWEET32': False,
                                                       'LUCKY13': False,
                                                         'FREAK': False,
                                                   'Compression': False,
                                                  'SCSV_SUPPORT': False,
                                          'Client_Renegotiation': False,
                                             'Support for SSLv2': False,
                                             'Support for SSLv3': False,
                                           'Support for TLS_1.0': False,
                                           'Support for TLS_1.1': False,
                                        'No Support for TLS_1.3': False,
                                               'Support for MD5': False,
                                              'Support for SHA1': False,
                                      'Support for NULL ciphers': False,
                                 'Support for Anonymous ciphers': False,
                                    'Support for Export ciphers': False,
                                        'Support for RC ciphers': False,
                                       'Support for DES ciphers': False,
                                      'Support for 3DES ciphers': False,
                                      'Support for IDEA ciphers': False,
                               'Support for ciphers without PFS': False,
                                       'Support for CBC ciphers': False
                                            }

                                            # DNS_Name
                                            if (Result_Left == "DNS" and Result_Right == ""):   Dict_Overview_SSL[Target]['DNS'] = ""
                                            elif (Result_Left == "DNS" and Result_Right != ""): Dict_Overview_SSL[Target]['DNS'] = Result_Right


                                            # Protocol_Check
                                            if (_['Protocol'] == "SSLv2" or _['Protocol'] == "SSLv23"):
                                                Dict_Overview_SSL[Target]['Support for SSLv2']   = True
                                            elif (_['Protocol'] == "SSLv3"):
                                                Dict_Overview_SSL[Target]['Support for SSLv3']   = True
                                            elif (_['Protocol'] == "TLS_1.0"):
                                                Dict_Overview_SSL[Target]['Support for TLS_1.0'] = True
                                            elif (_['Protocol'] == "TLS_1.1"):
                                                Dict_Overview_SSL[Target]['Support for TLS_1.1'] = True

                                            for Cipher in _['Ciphers']:
                                                Temp_Arr = [_['Protocol'],Cipher['Key_Size'],Cipher['Name']]

                                                # Check_Ciphers
                                                if ("MD5" in Cipher['Name']):
                                                    Dict_Overview_SSL[Target]['Support for MD5']               = True
                                                elif ("SHA1" in Cipher['Name']):
                                                    Dict_Overview_SSL[Target]['Support for SHA1']              = True
                                                elif ("NULL" in Cipher['Name']):
                                                    Dict_Overview_SSL[Target]['Support for NULL ciphers']      = True
                                                elif ("ANON" in Cipher['Name']):
                                                    Dict_Overview_SSL[Target]['Support for Anonymous ciphers'] = True
                                                elif ("EXPORT" in Cipher['Name'] or "EXP" in Cipher['Name']):
                                                    Dict_Overview_SSL[Target]['Support for Export ciphers']    = True
                                                elif ("RC2" in Cipher['Name'] or "RC4" in Cipher['Name']):
                                                    Dict_Overview_SSL[Target]['Support for RC ciphers']        = True
                                                elif ("DES" in Cipher['Name'] and not "3DES" in Cipher['Name']):
                                                    Dict_Overview_SSL[Target]['Support for DES ciphers']       = True
                                                elif ("DES" in Cipher['Name'] and "3DES" in Cipher['Name']):
                                                    Dict_Overview_SSL[Target]['Support for 3DES ciphers']      = True
                                                elif ("IDEA" in Cipher['Name']):
                                                    Dict_Overview_SSL[Target]['Support for IDEA ciphers']      = True
                                                elif ("CBC" in Cipher['Name']):
                                                    Dict_Overview_SSL[Target]['Support for CBC ciphers']       = True

                                                # Write_Bad_Ciphers
                                                if (Cipher['Encryption'] != None):
                                                    Temp_Arr.append(Cipher['Encryption'])
                                                if (Cipher['Type'] != None):
                                                    Temp_Arr.append(Cipher['Type'])
                                                if (Cipher['Hash_Algorithm'] != None):
                                                    Temp_Arr.append(Cipher['Hash_Algorithm'])

#                                                if (Cipher['Curve_Name'] != None and Cipher['Curve_Name'] != ''):
#                                                    Temp_Arr.append(Cipher['Curve_Name'])
#                                                else: Temp_Arr.append('-')
#                                                if (Cipher['Type'] != '' and Cipher['Curve_Size'] != '' and Cipher['Curve_Size'] != None):
#                                                    Temp_Arr.append(f"{Cipher['Type']}_{Cipher['Curve_Size']}")
#                                                else: Temp_Arr.append('-')
                                                writer.writerow(Array_Temp + Temp_Arr)


                                elif (Result_Left == "Good_Ciphers"):
                                    for _ in Result_Right:
                                        if (_['Protocol'] != "" and _['Ciphers'] != []):
                                            for Cipher in _['Ciphers']:
                                                Temp_Arr = [_['Protocol'],Cipher['Key_Size'],Cipher['Name']]

                                                if (Cipher['Encryption'] != None):
                                                    Temp_Arr.append(Cipher['Encryption'])
                                                if (Cipher['Type'] != None):
                                                    Temp_Arr.append(Cipher['Type'])
                                                if (Cipher['Hash_Algorithm'] != None):
                                                    Temp_Arr.append(Cipher['Hash_Algorithm'])

#                                                if (Cipher['Curve_Name'] != None and Cipher['Curve_Name'] != ''):
#                                                    Temp_Arr.append(Cipher['Curve_Name'])
#                                                else: Temp_Arr.append('-')
#                                                if (Cipher['Type'] != '' and Cipher['Curve_Size'] != '' and Cipher['Curve_Size'] != None):
#                                                    Temp_Arr.append(f"{Cipher['Type']}_{Cipher['Curve_Size']}")
#                                                else: Temp_Arr.append('-')
                                                writer_Third.writerow(Array_Temp + Temp_Arr)
                                elif (Result_Left == "SSL_Vulns"):
                                    if (Target not in Dict_Overview_SSL):
                                                Dict_Overview_SSL[Target] = {
                                                           'DNS': "",
                                'Insecure_Certificate_Signature': False,
                                           'Certificate_Expired': False,
                                                   'DHE <= 1024': False,
                                                    'HEARTBLEED': False,
                                                 'CCS_Injection': False,
                                                         'ROBOT': False,
                                                         'BEAST': False,
                                                         'CRIME': False,
                                                         'DROWN': False,
                                                        'LOGJAM': False,
                                                        'POODLE': False,
                                                       'SWEET32': False,
                                                       'LUCKY13': False,
                                                         'FREAK': False,
                                                   'Compression': False,
                                                  'SCSV_SUPPORT': False,
                                          'Client_Renegotiation': False,
                                             'Support for SSLv2': False,
                                             'Support for SSLv3': False,
                                           'Support for TLS_1.0': False,
                                           'Support for TLS_1.1': False,
                                        'No Support for TLS_1.3': False,
                                               'Support for MD5': False,
                                              'Support for SHA1': False,
                                      'Support for NULL ciphers': False,
                                 'Support for Anonymous ciphers': False,
                                    'Support for Export ciphers': False,
                                        'Support for RC ciphers': False,
                                       'Support for DES ciphers': False,
                                      'Support for 3DES ciphers': False,
                                      'Support for IDEA ciphers': False,
                               'Support for ciphers without PFS': False,
                                       'Support for CBC ciphers': False
                                            }

                                    # SSL_Vulns
                                    for _ in Result_Right:
                                        Temp_Arr = []
                                        if (type(Result_Right[_]) != bool): Length_Vuln = len(Result_Right[_])
                                        else:                               Length_Vuln = 1

                                        if (_ == "POODLE" and (Result_Right[_] != "False" and Result_Right[_] != False and Length_Vuln > 0)):
                                            Temp_Arr = ['The system is vulnerable for POODLE (CVE-2014-3566)']
                                            Dict_Overview_SSL[Target]['POODLE'] = True

                                        elif (_ == "CRIME" and (Result_Right[_] != "False" and Result_Right[_] != False and Length_Vuln > 0)):
                                            Temp_Arr = ['The system is vulnerable for CRIME (CVE-2012-4929)']
                                            Dict_Overview_SSL[Target]['CRIME'] = True

                                        elif (_ == "DROWN" and (Result_Right[_] != "False" and Result_Right[_] != False and Length_Vuln > 0)):
                                            Temp_Arr = ['The system is vulnerable for DROWN (CVE-2016-0800)']
                                            Dict_Overview_SSL[Target]['DROWN'] = True

                                        elif (_ == "HEARTBLEED" and (Result_Right[_] != "False" and Result_Right[_] != False and Length_Vuln > 0)):
                                            Temp_Arr = ['The system is vulnerable for HEARTBLEED (CVE-2014-0160)']
                                            Dict_Overview_SSL[Target]['HEARTBLEED'] = True

                                        elif (_ == "CCS_INJECTION" and (Result_Right[_] != "False" and Result_Right[_] != False and Length_Vuln > 0)):
                                            Temp_Arr = ['The system is vulnerable for CCS_INJECTION (CVE-2014-0224)']
                                            Dict_Overview_SSL[Target]['CCS_Injection'] = True

                                        elif (_ == "ROBOT" and (Result_Right[_] != "False" and Result_Right[_] != False and Length_Vuln > 0)):
                                            Temp_Arr = ['The system is vulnerable for ROBOT (CVE-2017-13099)']
                                            Dict_Overview_SSL[Target]['ROBOT'] = True

                                        elif (_ == "CLIENT_RENEGOTIATION_DOS" and (Result_Right[_] != "False" and Result_Right[_] != False and Length_Vuln > 0)):
                                            Temp_Arr = ['The system is vulnerable for CLIENT_RENEGOTIATION_DOS (CVE-2011-1473)']
                                            Dict_Overview_SSL[Target]['Client_Renegotiation'] = True

                                        elif (_ == "FALLBACK_SCSV"):
                                            print (Result_Right[_])

                                        elif (_ == "FALLBACK_SCSV" and (Result_Right[_] != "False" and Result_Right[_] != False and Length_Vuln > 0)):
                                            Temp_Arr = ['The system does not support FALLBACK_SCSV as protection against downgrade attacks']
                                            Dict_Overview_SSL[Target]['SCSV_SUPPORT'] = True

                                        elif (_ == "BREACH" and (Result_Right[_] != "False" and Result_Right[_] != False and Length_Vuln > 0)):
                                            Temp_Arr = ['The system is vulnerable for BREACH (CVE-2013-3587)']
                                            Dict_Overview_SSL[Target]['BREACH'] = True

                                        elif (_ == "LOGJAM" and (Result_Right[_] != "False" and Result_Right[_] != False and Length_Vuln > 0)):
                                            Temp_Arr = ['The system is vulnerable for LOGJAM (CVE-2015-4000)']
                                            Dict_Overview_SSL[Target]['LOGJAM'] = True

                                        elif (_ == "BEAST" and (Result_Right[_] != "False" and Result_Right[_] != False and Length_Vuln > 0)):
                                            Temp_Arr = ['The system is vulnerable for BEAST (CVE-2011-3389)']
                                            Dict_Overview_SSL[Target]['BEAST'] = True

                                        elif (_ == "LUCKY13" and (Result_Right[_] != "False" and Result_Right[_] != False and Length_Vuln > 0)):
                                            Temp_Arr = ['The system is potentially vulnerable for LUCKY13 (CVE-2013-0169)']
                                            Dict_Overview_SSL[Target]['LUCKY13'] = True

                                        elif (_ == "SWEET32" and (Result_Right[_] != "False" and Result_Right[_] != False and Length_Vuln > 0)):
                                            Temp_Arr = ['The system is potentially vulnerable for SWEET32 (CVE-2016-6329)']
                                            Dict_Overview_SSL[Target]['SWEET32'] = True

                                        elif (_ == "FREAK" and (Result_Right[_] != "False" and Result_Right[_] != False and Length_Vuln > 0)):
                                            Temp_Arr = ['The system is vulnerable for FREAK (CVE-2015-0204)']
                                            Dict_Overview_SSL[Target]['FREAK'] = True

                                        elif (_ == "ANONYMOUS" and (Result_Right[_] != "False" and Result_Right[_] != False and Length_Vuln > 0)):
                                            Temp_Arr = ['The system is using anonymous ciphers']
                                            Dict_Overview_SSL[Target]['Support for Anonymous ciphers'] = True

                                        elif (_ == "PFS" and (Result_Right[_] != "False" and Result_Right[_] != False and Length_Vuln > 0)):
                                            Temp_Arr = ["The system is using ciphers without Perfect Forward Security (PFS)"]
                                            Dict_Overview_SSL[Target]['Support for ciphers without PFS'] = True

                                        elif (_ == "INACTIVE_TLS_1_3" and (Result_Right[_] != "False" and Result_Right[_] != False and Length_Vuln > 0)):
                                            Temp_Arr = ['The system has TLS 1.3 disabled.']
                                            Dict_Overview_SSL[Target]['No Support for TLS_1.3'] = True

                                        if (Temp_Arr != []):
                                            writer_Sec.writerow(Array_Temp + Temp_Arr)
                                elif (Result_Left == "Curves"):
                                    pass

                        # Filter_SSL_Overview_File
                        Array_Temp_Second, Array_Temp_Head = [], []
                        if (Write_Fourth_Mode == 'w'):
                            for _ in Dict_Overview_SSL:
                                Array_Temp_Head.append('Host')
                                for j in Dict_Overview_SSL[_]:
                                    if (j not in Array_Temp_Head):
                                        Array_Temp_Head.append(j)
                                break
                            writer_Overview.writerow(Array_Temp_Head)

                        for _ in Dict_Overview_SSL:
                            Array_Temp_Second.append(_)
                            for j in Dict_Overview_SSL[_]:
                                #print(f'{j} : {Dict_Overview_SSL[_][j]}')
                                if (j == "DNS" and Dict_Overview_SSL[_][j] != ''):
                                    Array_Temp_Second.append(Dict_Overview_SSL[_][j])
                                elif (j == "DNS" and Dict_Overview_SSL[_][j] == ''):
                                    Array_Temp_Second.append('-')

                                if (j != "DNS" and Dict_Overview_SSL[_][j] == False):
                                    Array_Temp_Second.append("✓")
                                elif (j != "DNS" and Dict_Overview_SSL[_][j] == True):
                                    Array_Temp_Second.append("X")

                            if (Array_Temp_Second.count('✓') != len(Dict_Overview_SSL[_])-1):
                                writer_Overview.writerow(Array_Temp_Second)
                            else:
                                Standard.Remove_From_Filtered_File(join(location, 'result_ssl_overview.csv'), _)
                            Array_Temp_Second = []

        Standard.Remove_Empty_Filter_File(join(location, 'result_ssl_bad_ciphers.csv')), Standard.Remove_Empty_Filter_File(join(location, 'result_ssl_vulns.csv')), Standard.Remove_Empty_Filter_File(join(location, 'result_ssl_good_ciphers.csv')), Standard.Remove_Empty_Filter_File(join(location, 'result_ssl_overview.csv'))
        Standard.Remove_Empty_Filter_File(join(location, 'affected_ssl_vulns.txt')), Standard.Remove_Empty_Filter_File(join(location, 'affected_ssl_targets.txt'))
