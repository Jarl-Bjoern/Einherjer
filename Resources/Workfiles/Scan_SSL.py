#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables     import *
from ..Workfiles.Scan_Host_Name   import Get_Host_Name
from ..Standard_Operations.Logs   import Logs
from ..Standard_Operations.Colors import Colors

def SSL_Vulns(array_ssl_targets, ssl_timeout, Location, Array_Result_Filter = ['http_headers', 'certificate_info','rejected_cipher_suites','rejected_curves'], Start_Scan = datetime.now(), Temp = ""):
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

            # Remove_Slashes
            if (URL.count('/') > 1):
                Temp   = URL.split('/')[0]
                URL    = Temp
        else: Port = 443

        try:
            Array_Attack.append(
                ServerScanRequest(
                    server_location=ServerNetworkLocation(
                        hostname=URL,
                        ip_address=URL,
                        port=Port
                    ),
                    network_configuration=ServerNetworkConfiguration(
                        URL,
                        network_timeout=ssl_timeout,
                        network_max_retries=2
                    )
                )
            )
        except (ConnectionResetError, ServerHostnameCouldNotBeResolved):
            Logs.Log_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.BLUE+'SSL-Check\n'
                +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +f'{strftime("%Y-%m-%d_%H:%M:%S")} - {url} - It was not possible to connect to the target\n',
                join(Location, 'Logs')
            )

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
            Dict_Temp_Ciphers =  {
                'Anonymous':                "",
                'Key_Size':                 "",
                'Name':                     "",
                'Curve_Name':               "",
                'Type':                     "",
                'Curve_Size':               ""
            }
            Dict_Full_SSL = {
                'DNS':                      "",
                'Ciphers':                  [],
                'SSL_Vulns':                {},
                'Curves':                   []
            }
            Dict_SSL_Vulns = {
                'CRIME':                    "",
                'LOGJAM':                   "",
                'HEARTBLEED':               "",
                'CCS_INJECTION':            "",
                'ROBOT':                    "",
                'CLIENT_RENEGOTIATION_DOS': "",
                'SWEET32':                  "",
                'LUCKY13':                  "",
                'FALLBACK_SCSV':            ""
            }

            if (server_scan_result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY):
                Logs.Log_File(
                    Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                    +Colors.BLUE+'SSL-Check\n'+Colors.YELLOW
                    +'-----------------------------------------------------------------------------------------------------------\n'
                    +f'{strftime("%Y-%m-%d_%H:%M:%S")} - {server_scan_result.server_location.hostname} - It was not possible to connect to the target\n',
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

                for _ in json_loads(temp_json_output)['server_scan_results']:
                    Dict_Full_Output[f"{_['server_location']['ip_address']}:{_['server_location']['port']}"] = {}
                    Scan_Result = _['scan_result']
                    if (Scan_Result != None):
                        for i in Scan_Result:
                            if (i not in Array_Result_Filter):
                                Deep_Result = Scan_Result[i]['result']
                                try:
                                    for k in Deep_Result:
                                        if (k not in Array_Result_Filter):
                                            if (k == 'accepted_cipher_suites'):
                                                for z in Deep_Result[k]:
                                                    Cipher_Filter = findall(rf'{Array_TLS_Algorithms[0]}', z['cipher_suite']['name'])
                                                    if (Cipher_Filter != []):
                                                        Dict_Temp_Ciphers['Anonymous']      = z['cipher_suite']['is_anonymous']
                                                        Dict_Temp_Ciphers['Key_Size']       = z['cipher_suite']['key_size']
                                                        Dict_Temp_Ciphers['Name']           = z['cipher_suite']['name']
                                                        if (z['ephemeral_key'] != None):
                                                            Dict_Temp_Ciphers['Curve_Name'] = z['ephemeral_key']['curve_name']
                                                            Dict_Temp_Ciphers['Type']       = z['ephemeral_key']['type_name']
                                                            Dict_Temp_Ciphers['Curve_Size'] = z['ephemeral_key']['size']
                                                        if (Dict_Temp_Ciphers not in Dict_Ciphers['Ciphers']):
                                                            Dict_Ciphers['Ciphers'].append(Dict_Temp_Ciphers)
                                                            Dict_Temp_Ciphers = {
                                                                'Anonymous':  "",
                                                                'Key_Size':   "",
                                                                'Name':       "",
                                                                'Curve_Name': "",
                                                                'Type':       "",
                                                                'Curve_Size': ""
                                                            }
                                            elif (k == 'tls_version_used'):
                                                TLS_Version = Deep_Result[k]
                                            elif (k == 'is_tls_version_supported'):
                                                Supported_Version = Deep_Result[k]
                                            elif (k == 'is_vulnerable_to_heartbleed'):
                                                Dict_SSL_Vulns['HEARTBLEED'] = Deep_Result[k]
                                            elif (k == 'is_vulnerable_to_ccs_injection'):
                                                Dict_SSL_Vulns['CCS_INJECTION'] = Deep_Result[k]
                                            elif (k == 'robot_result'):
                                                if ('NOT_VULNERABLE' in Deep_Result[k]):
                                                    Dict_SSL_Vulns['ROBOT'] = False
                                                else:
                                                    Dict_SSL_Vulns['ROBOT'] = True
                                            elif (k == 'is_vulnerable_to_client_renegotiation_dos'):
                                                Dict_SSL_Vulns['CLIENT_RENEGOTIATION_DOS'] = Deep_Result[k]
                                            elif (k == 'supports_compression'):
                                                Dict_SSL_Vulns['CRIME'] = Deep_Result[k]
                                            elif (k == 'supports_fallback_scsv'):
                                                Dict_SSL_Vulns['FALLBACK_SCSV'] = Deep_Result[k]
                                            elif (k == 'supported_curves'):
                                                for z in Deep_Result[k]:
                                                    if (z['name'] not in Dict_Full_SSL['Curves']):
                                                        Dict_Full_SSL['Curves'].append(z['name'])
                                            elif (k == 'supports_ecdh_key_exchange'):
                                                pass
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
                                                Dict_Ciphers['Protocol'] = f'{TLS_Version}'
                                                Dict_Full_SSL['Ciphers'].append(Dict_Ciphers)
                                                TLS_Version, Supported_Version = "",""
                                                Dict_Ciphers = {'Protocol':"", 'Ciphers': []}

                                except TypeError:
                                    Logs.Log_File(
                                        Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                                        +Colors.BLUE+'SSL-Check\n'+Colors.YELLOW
                                        +'-----------------------------------------------------------------------------------------------------------\n'
                                        +f'{strftime("%Y-%m-%d_%H:%M:%S")} - {_["server_location"]["ip_address"]}:{_["server_location"]["port"]} - It was not possible to connect to the target\n',
                                        join(Location, 'Logs')
                                    )

                        Dict_Full_SSL['SSL_Vulns'] = Dict_SSL_Vulns
                        Dict_Full_Output[f"{_['server_location']['ip_address']}:{_['server_location']['port']}"] = Dict_Full_SSL

                        Logs.Log_File(
                            Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                            +Colors.BLUE+'SSL-Check\n'
                            +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                            +Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {_["server_location"]["ip_address"]}:{_["server_location"]["port"]}'
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
            +f'{strftime("%Y-%m-%d_%H:%M:%S")} - {url} - It was not possible to connect to the target\n',
            join(Location, 'Logs')
        )

    return Dict_Full_Output
