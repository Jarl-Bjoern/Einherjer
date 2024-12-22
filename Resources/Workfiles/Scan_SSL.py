#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables     import *
from ..Workfiles.Scan_Host_Name   import Get_Host_Name
from ..Standard_Operations.Logs   import Logs
from ..Standard_Operations.Colors import Colors

def SSL_Vulns(array_ssl_targets, ssl_timeout, Location, dict_proxies, dict_auth, Array_Result_Filter = ['http_headers','rejected_cipher_suites','rejected_curves'], Start_Scan = datetime.now(), Temp = ""):
    # Variables
    TLS_Version, Supported_Version, Array_Attack, Dict_Full_Output = "","",[],{}

    # Target_Preparation
    for url in array_ssl_targets:
        # Target_Filter
        if ('ssl://' in url):     URL = url.split('ssl://')[1]
        elif ('https://' in url): URL = url.split('https://')[1]

        # Port_Filter
        if (url.count(':') > 1):
            Temp, Port = URL.split(':')
            URL        = Temp
        else: Port = 443

        # Remove_Single_Slash
        if (URL.count('/') == 1):
            Temp   = URL.split('/')[0]
            URL    = Temp

        # URL_Encode
        elif (URL.count('/') > 1):
            Temp   = url_encode(URL).replace("2%F", "/")
            URL    = Temp

        print (dict_proxies)
        print (dict_auth)

        # Setup_Auth_Method
        #ClientAuthenticationCredentials(
        #    certificate_chain_path,
        #    key_path,
        #    key_password='',
        #    key_type=OpenSslFileTypeEnum.PEM
        #)

        # Configure_Proxy_Settings
        SSL_Scanning_Proxy = None

        try:
            if (SSL_Scanning_Proxy != None):
                Array_Attack.append(
                        ServerScanRequest(
                            server_location=ServerNetworkLocation(
                                hostname=URL,
                                ip_address=URL,
                                port=Port,
                                http_proxy_settings=SSL_Scanning_Proxy
                            ),
                            network_configuration=ServerNetworkConfiguration(
                                URL,
                                network_timeout=ssl_timeout,
                                network_max_retries=5
                            )
                        )
                    )
            else:
                Array_Attack.append(
                    ServerScanRequest(
                        server_location=ServerNetworkLocation(
                            hostname=URL,
                            ip_address=URL,
                            port=Port,
                        ),
                        network_configuration=ServerNetworkConfiguration(
                            URL,
                            network_timeout=ssl_timeout,
                            network_max_retries=5
                        )
                    )
                )
        except ConnectionResetError:
            Logs.Log_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.BLUE+'SSL-Check\n'
                +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.RED+f'{strftime("%Y-%m-%d %H:%M:%S")} - {url} - It was not possible to connect to the target\n',
                join(Location, 'Logs')
            )
        except ServerHostnameCouldNotBeResolved:
            Logs.Log_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.BLUE+'SSL-Check\n'
                +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.RED+f'{strftime("%Y-%m-%d %H:%M:%S")} - {url} - It was not possible to resolve the server hostname\n',
                join(Location, 'Logs')
            )
        except CryptographyDeprecationWarning: pass

    # Scanning_Process
    try:
        scanner = Scanner(
            per_server_concurrent_connections_limit=25,
            concurrent_server_scans_limit=100
        )
        scanner.queue_scans(Array_Attack)

        for server_scan_result in scanner.get_results():
            # Dictionaries
            Dict_Ciphers = {
                'Protocol':                 "",
                'Ciphers':                  []
            }
            Dict_Good_Ciphers = {
                'Protocol':                 "",
                'Ciphers':                  []
            }
            Dict_Temp_Ciphers =  {
                'Key_Size':                 "",
                'Name':                     "",
                'Curve_Name':               "",
                'Type':                     "",
                'Curve_Size':               "",
                "Encryption":               "",
                "Hash_Algorithm":           ""
            }
            Dict_Temp_Good_Ciphers = {
                'Key_Size':                 "",
                'Name':                     "",
                'Curve_Name':               "",
                'Type':                     "",
                'Curve_Size':               "",
                "Encryption":               "",
                "Hash_Algorithm":           ""
            }
            Dict_Full_SSL = {
                'DNS':                      "",
                'Ciphers':                  [],
                'SSL_Vulns':                {},
                'Curves':                   [],
                'Good_Ciphers':             []
            }
            Dict_SSL_Vulns = {
                'BEAST':                    "",
                'CRIME':                    "",
                'DROWN':                    "",
                'LOGJAM':                   "",
                'HEARTBLEED':               "",
                'CCS_INJECTION':            "",
                'POODLE':                   "",
                'ROBOT':                    "",
                'CLIENT_RENEGOTIATION_DOS': "",
                'SWEET32':                  "",
                'LUCKY13':                  "",
                'FALLBACK_SCSV':            "",
                'FREAK':                    "",
                'Missing_PFS':              "",
                'ANONYMOUS':                "",
                'INACTIVE_TLS_1_3':         ""
            }

            if (server_scan_result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY):
                Logs.Log_File(
                    Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                    +Colors.BLUE+'SSL-Check\n'+Colors.YELLOW
                    +'-----------------------------------------------------------------------------------------------------------\n'
                    +Colors.RED+f'{strftime("%Y-%m-%d %H:%M:%S")} - {url} - It was not possible to connect to the target\n',
                    join(Location, 'Logs')
                )
            elif (server_scan_result.scan_status == ServerScanStatusEnum.COMPLETED):
                json_output = SslyzeOutputAsJson(
                    server_scan_results=[
                        ServerScanResultAsJson.from_orm(server_scan_result)
                    ],
                    date_scans_started=Start_Scan,
                    date_scans_completed=datetime.now()
                )
                temp_json_output = json_output.json(sort_keys=True, indent=4, ensure_ascii=True)

                # Output_Backup
                Backup_Out = join(Location, 'SSL_Backup')
                if (not exists(Backup_Out)):
                    makedirs(Backup_Out)
                    Output_File_Name = f"SSL_Scan_Out_0.json"
                else:
                    Temp_Counter_Array = []
                    for _ in listdir(Backup_Out):
                        Temp_Counter_Array.append(_[:-5].split('_')[-1:][0])
                    Temp_Counter_Array.sort()

                    Backup_Val       = Temp_Counter_Array[::-1][0]
                    Counter_Name     = int(Backup_Val)+1
                    Output_File_Name = f"SSL_Scan_Out_{Counter_Name}.json"

                with open(join(Backup_Out, Output_File_Name), 'w', encoding='UTF-8') as f:
                    f.write(temp_json_output)


                # Results
                for _ in json_loads(temp_json_output)['server_scan_results']:
                    Log_Target = f"{_['server_location']['ip_address']}:{_['server_location']['port']}"
                    Dict_Full_Output[Log_Target] = {}
                    Scan_Result = _['scan_result']
                    if (Scan_Result != None):
                        for i in Scan_Result:
                            if (i not in Array_Result_Filter):
                                Deep_Result = Scan_Result[i]['result']
                                try:
                                    for k in Deep_Result:
                                        if (k not in Array_Result_Filter):
                                            # Certificate_Information
#                                            if (k == 'certificate_deployments'):
#                                                print (Deep_Result[k])

                                            # Cipher_Suites
                                            if (k == 'accepted_cipher_suites'):
                                                for z in Deep_Result[k]:
                                                    Cipher_Filter = findall(rf'{Array_TLS_Algorithms[0]}', z['cipher_suite']['name'])
                                                    if (Cipher_Filter != []):
                                                        # Bad_Ciphers
                                                        Dict_Temp_Ciphers['Key_Size']       = z['cipher_suite']['key_size']
                                                        Dict_Temp_Ciphers['Name']           = z['cipher_suite']['name']

                                                        # Anonymous_Ciphers
                                                        if (z['cipher_suite']['is_anonymous'] == True):
                                                            Dict_SSL_Vulns['ANONYMOUS'] = z['cipher_suite']['is_anonymous']

                                                        # SWEET32, Usage of DES ciphers
                                                        if ("DES" in z['cipher_suite']['name']):
                                                            Dict_SSL_Vulns['SWEET32'] = True

                                                        # LUCKY13, Usage of CBC ciphers
                                                        if ("CBC" in z['cipher_suite']['name']):
                                                            Dict_SSL_Vulns['LUCKY13'] = True
                                                            # SWEET32, Usage of CBC ciphers with key size lower than 128
                                                            if (z['cipher_suite']['key_size'] < 128):
                                                                Dict_SSL_Vulns['SWEET32'] = True

                                                        # FREAK, Usage of Export ciphers
                                                        if ("EXPORT" in z['cipher_suite']['name']):
                                                            Dict_SSL_Vulns['FREAK'] = True

                                                        # Curve
                                                        if (z['ephemeral_key'] != None):
                                                            Dict_Temp_Ciphers['Curve_Name'] = z['ephemeral_key']['curve_name']
                                                            Dict_Temp_Ciphers['Type']       = z['ephemeral_key']['type_name']
                                                            Dict_Temp_Ciphers['Curve_Size'] = z['ephemeral_key']['size']
                                                        else:
                                                            # PFS, cipher suites without ephemeral
                                                            if ("DHE" not in z['cipher_suite']['name']):
                                                                Dict_SSL_Vulns['Missing_PFS'] = True

                                                            # RSA
                                                            if ("RSA" in z['cipher_suite']['name']):
                                                                Dict_Temp_Ciphers['Type']   = "RSA"

                                                        # Encryption
                                                        if ("TLS" in z['cipher_suite']['name']):
                                                            Temp_Cipher = z['cipher_suite']['name'].split('TLS_')[1]
                                                            if ("WITH_" in Temp_Cipher):
                                                                Temp_Cipher = Temp_Cipher.split('WITH_')[1]
                                                            if ("_SHA" in Temp_Cipher):
                                                                Dict_Temp_Ciphers['Encryption']     = Temp_Cipher.split('_SHA')[0]
                                                                Dict_Temp_Ciphers['Hash_Algorithm'] = Temp_Cipher.split('_')[-1]
                                                            else:
                                                                Dict_Temp_Ciphers['Encryption_Type'], Dict_Temp_Ciphers['Hash_Algorithm'] = Temp_Cipher, '-'

                                                        if (Dict_Temp_Ciphers not in Dict_Ciphers['Ciphers']):
                                                            Dict_Ciphers['Ciphers'].append(Dict_Temp_Ciphers)
                                                            Dict_Temp_Ciphers = {
                                                                'Key_Size':   "",
                                                                'Name':       "",
                                                                'Curve_Name': "",
                                                                'Type':       "",
                                                                'Curve_Size': "",
                                                                "Encryption": "",
                                                                "Hash_Algorithm": ""
                                                            }
                                                    else:
                                                        # Good_Ciphers
                                                        Dict_Temp_Good_Ciphers['Key_Size']       = z['cipher_suite']['key_size']
                                                        Dict_Temp_Good_Ciphers['Name']           = z['cipher_suite']['name']
                                                        if ("TLS" in z['cipher_suite']['openssl_name']):
                                                            Temp_Cipher = z['cipher_suite']['openssl_name'].split('TLS_')[1]
                                                            if ("WITH_" in Temp_Cipher):
                                                                Temp_Cipher = Temp_Cipher.split('WITH_')[1]
                                                            if ("_SHA" in Temp_Cipher):
                                                                Dict_Temp_Good_Ciphers['Encryption']     = Temp_Cipher.split('_SHA')[0]
                                                                Dict_Temp_Good_Ciphers['Hash_Algorithm'] = Temp_Cipher.split('_')[-1]
                                                            else:
                                                                Dict_Temp_Good_Ciphers['Encryption'], Dict_Temp_Good_Ciphers['Hash_Algorithm'] = Temp_Cipher, '-'

                                                        if (z['ephemeral_key'] != None):
                                                            Dict_Temp_Good_Ciphers['Curve_Name'] = z['ephemeral_key']['curve_name']
                                                            Dict_Temp_Good_Ciphers['Type']       = z['ephemeral_key']['type_name']
                                                            Dict_Temp_Good_Ciphers['Curve_Size'] = z['ephemeral_key']['size']
                                                        else:
                                                            if ("RSA" in z['cipher_suite']['name']):
                                                                Dict_Temp_Good_Ciphers['Type']   = "RSA"

                                                        # Encryption
                                                        if ("TLS" in z['cipher_suite']['name']):
                                                            Temp_Cipher = z['cipher_suite']['name'].split('TLS_')[1]
                                                            if ("WITH_" in Temp_Cipher):
                                                                Temp_Cipher = Temp_Cipher.split('WITH_')[1]
                                                            if ("_SHA" in Temp_Cipher):
                                                                Dict_Temp_Good_Ciphers['Encryption']     = Temp_Cipher.split('_SHA')[0]
                                                                Dict_Temp_Good_Ciphers['Hash_Algorithm'] = Temp_Cipher.split('_')[-1]
                                                            else:
                                                                Dict_Temp_Good_Ciphers['Encryption_Type'], Dict_Temp_Good_Ciphers['Hash_Algorithm'] = Temp_Cipher, '-'

                                                        if (Dict_Temp_Good_Ciphers not in Dict_Good_Ciphers['Ciphers']):
                                                            Dict_Good_Ciphers['Ciphers'].append(Dict_Temp_Good_Ciphers)
                                                            Dict_Temp_Good_Ciphers = {
                                                                'Key_Size':   "",
                                                                'Name':       "",
                                                                'Curve_Name': "",
                                                                'Type':       "",
                                                                'Curve_Size': "",
                                                                "Encryption": "",
                                                                "Hash_Algorithm": ""
                                                            }
                                            elif (k == 'tls_version_used'):
                                                TLS_Version = Deep_Result[k]
                                            elif (k == 'is_tls_version_supported'):
                                                Supported_Version = Deep_Result[k]

                                            # Heartbleed
                                            elif (k == 'is_vulnerable_to_heartbleed'):
                                                Dict_SSL_Vulns['HEARTBLEED'] = Deep_Result[k]

                                            # CCS
                                            elif (k == 'is_vulnerable_to_ccs_injection'):
                                                Dict_SSL_Vulns['CCS_INJECTION'] = Deep_Result[k]

                                            # Robot
                                            elif (k == 'robot_result'):
                                                if ('NOT_VULNERABLE' in Deep_Result[k]):
                                                    Dict_SSL_Vulns['ROBOT'] = False
                                                else:
                                                    Dict_SSL_Vulns['ROBOT'] = True

                                            # Client_Renegotiation_DoS
                                            elif (k == 'is_vulnerable_to_client_renegotiation_dos'):
                                                Dict_SSL_Vulns['CLIENT_RENEGOTIATION_DOS'] = Deep_Result[k]

                                            # CRIME
                                            elif (k == 'supports_compression'):
                                                Dict_SSL_Vulns['CRIME'] = Deep_Result[k]

                                            # SCSV
                                            elif (k == 'supports_fallback_scsv'):
                                                if (Deep_Result[k] == False):
                                                    Dict_SSL_Vulns['FALLBACK_SCSV'] = True

                                            elif (k == 'supported_curves'):
                                                for z in Deep_Result[k]:
                                                    if (z['name'] not in Dict_Full_SSL['Curves']):
                                                        Dict_Full_SSL['Curves'].append(z['name'])
                                            elif (k == 'supports_secure_renegotiation'           or
                                                  k == 'supports_early_data'                     or
                                                  k == 'session_id_attempted_resumptions_count'  or
                                                  k == 'session_id_resumption_result'            or
                                                  k == 'session_id_successful_resumptions_count' or
                                                  k == 'tls_ticket_attempted_resumptions_count'  or
                                                  k == 'tls_ticket_resumption_result'            or
                                                  k == 'tls_ticket_successful_resumptions_count'):
                                                    pass
                    #                        else:
                    #                            print (f'{k} : {Deep_Result[k]}')

                                            if (TLS_Version != "" and Supported_Version != ""):
                                                Dict_Ciphers['Protocol'], Dict_Good_Ciphers['Protocol'] = f'{TLS_Version}',f'{TLS_Version}'
                                                Dict_Full_SSL['Ciphers'].append(Dict_Ciphers)
                                                Dict_Full_SSL['Good_Ciphers'].append(Dict_Good_Ciphers)

                                                # BEAST
                                                if (TLS_Version == "TLS_1_0"):
                                                    for _ in Dict_Ciphers:
                                                        if ("CBC" in _):
                                                            Dict_SSL_Vulns['BEAST'] = True
                                                            break

                                                # POODLE
                                                if ("SSL" in TLS_Version):
                                                    for _ in Dict_Ciphers:
                                                        if ("CBC" in _):
                                                            Dict_SSL_Vulns['POODLE'], Dict_SSL_Vulns['BEAST'] = True, True
                                                            break

                                                # TLS_1_3_Check
                                                if (TLS_Version == "TLS_1_3" and Supported_Version == False):
                                                    Dict_SSL_Vulns['INACTIVE_TLS_1_3'] = True

                                                TLS_Version, Supported_Version = "",""
                                                Dict_Ciphers, Dict_Good_Ciphers = {'Protocol':"", 'Ciphers': []}, {'Protocol':"", 'Ciphers': []}

                                except TypeError:
                                    Logs.Log_File(
                                        Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                                        +Colors.BLUE+'SSL-Check\n'+Colors.YELLOW
                                        +'-----------------------------------------------------------------------------------------------------------\n'
                                        +Colors.RED+f'{strftime("%Y-%m-%d %H:%M:%S")} - {Log_Target} - There was a TypeError inside the filter process.\n',
                                        join(Location, 'Logs')
                                    )

                        Dict_Full_SSL['SSL_Vulns']   = Dict_SSL_Vulns
                        Dict_Full_Output[Log_Target] = Dict_Full_SSL

                        Logs.Log_File(
                            Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                            +Colors.BLUE+'SSL-Check\n'
                            +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                            +Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {Log_Target}'
                            +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
                            +Colors.ORANGE+'\nEinherjer Output'
                            +Colors.RED+' -> '+Colors.RESET+f'{Dict_Full_SSL}'+Colors.BLUE
                            +'\n-----------------------------------------------------------------------------------------------------------\n\n'+Colors.RESET,
                            join(Location, 'Logs')
                        )

    except (ConnectionResetError):
        Logs.Log_File(
            Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
            +Colors.BLUE+'SSL-Check\n'+Colors.YELLOW
            +'-----------------------------------------------------------------------------------------------------------\n'
            +Colors.RED+f'{strftime("%Y-%m-%d %H:%M:%S")} - {url} - It was not possible to connect to the target\n',
            join(Location, 'Logs')
        )

    return Dict_Full_Output
