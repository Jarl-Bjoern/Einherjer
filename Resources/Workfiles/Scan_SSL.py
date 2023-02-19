#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

def Scan_SSL(Dict_Full_SSL = {}, Dict_SSL_Ciphers = {}, Dict_SSL_Vulns = {'CRIME': "", 'LOGJAM': "", 'HEARTBLEED': "", 'CCS_INJECTION': "", 'ROBOT': "", 'CLIENT_RENEGOTIATION_DOS': "", 'SWEET32': "", 'LUCKY13': "", 'FALLBACK_SCSV': ""}, Array_Result_Filter = ['http_headers', 'certificate_info','rejected_cipher_suites','rejected_curves'], Start_Scan = datetime.now()):
    Array_Targets, Array_SSL_Targets = ["127.0.0.1:8834"], []
    TLS_Version, Supported_Version, Temp_Array_Ciphers, Temp_Array_Ephemeral = "","",[],[]

    for i in Array_Targets:
        if (':' in i):
            Temp_Target = i.split(':')
            try: Array_SSL_Targets.append(ServerScanRequest(server_location=ServerNetworkLocation(hostname=Temp_Target[0], port=Temp_Target[1])))
            except ServerHostnameCouldNotBeResolved:
                print ("Error resolving the supplied hostname")

    scanner = Scanner()
    scanner.queue_scans(Array_SSL_Targets)

    for server_scan_result in scanner.get_results():
        json_output = SslyzeOutputAsJson(server_scan_results=[ServerScanResultAsJson.from_orm(server_scan_result)],date_scans_started=Start_Scan,date_scans_completed=datetime.now())
        temp_json_output = json_output.json(sort_keys=True, indent=4, ensure_ascii=True)

    for _ in json_loads(temp_json_output)['server_scan_results']:
        Scan_Result = _['scan_result']
        for i in Scan_Result:
            if (i not in Array_Result_Filter):
                Deep_Result = Scan_Result[i]['result']
                for k in Deep_Result:
                    if (k not in Array_Result_Filter):
                        if (k == 'accepted_cipher_suites'):
                            for z in Deep_Result[k]:
                                for y in z['cipher_suite']:
                                    Temp_Array_Ciphers.append(f"{y} : {z['cipher_suite'][y]}")
                                for x in z['ephemeral_key']:
                                    Temp_Array_Ephemeral.append(f"{x} : {z['ephemeral_key'][x]}")
                        elif (k == 'tls_version_used'):
                            TLS_Version = Deep_Result[k]
                        elif (k == 'is_tls_version_supported'):
                            Supported_Version = Deep_Result[k]
                        else:
                            print (f'{k} : {Deep_Result[k]}')

                        if (TLS_Version != "" and Supported_Version != "" and Temp_Array_Ciphers == []):
                            print (f'{TLS_Version} : {Supported_Version}')
                            TLS_Version, Supported_Version = "",""
                        elif (TLS_Version != "" and Supported_Version != "" and Temp_Array_Ciphers != []):
                            print (f'{TLS_Version} : {Supported_Version}\n\n{Temp_Array_Ciphers}\n\n{Temp_Array_Ephemeral}')
                            TLS_Version, Supported_Version, Temp_Array_Ciphers, Temp_Array_Ephemeral = "","",[],[]


    return Dict_Full_SSL
