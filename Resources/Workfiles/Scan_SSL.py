#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

def SSL_Vulns(Dict_Full_SSL = {}, Dict_SSL_Ciphers = {}, Dict_SSL_Vulns = {'CRIME': "", 'LOGJAM': "", 'HEARTBLEED': "", 'CCS_INJECTION': "", 'ROBOT': "", 'CLIENT_RENEGOTIATION_DOS': "", 'SWEET32': "", 'LUCKY13': "", 'FALLBACK_SCSV': ""}, Array_Result_Filter = ['http_headers', 'certificate_info','rejected_cipher_suites','rejected_curves'], Start_Scan = datetime.now()):
    Array_Targets, Array_SSL_Targets = ["127.0.0.1:8834"], []
    TLS_Version, Supported_Version, Temp_Array_Ciphers, Temp_Array_Ephemeral = "","",[],[]

    if ('http://' in url): URL = url.split('http://')[1]
    elif ('https://' in url): URL = url.split('https://')[1]

    if (url.count(':') > 1): Port = url.split(':')[2]
    else: Port = 443

    try: Array_SSL_Targets.append(ServerScanRequest(server_location=ServerNetworkLocation(hostname=URL, port=Port)))
    except ServerHostnameCouldNotBeResolved:
        Logs.Log_File(f'{strftime("%Y-%m-%d_%H:%M:%S")} - {url} - It was not possible to connect to the website\n')

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
                        elif (k == 'is_vulnerable_to_heartbleed'):
                            Dict_SSL_Vulns['HEARTBLEED'] = Deep_Result[k]
                        elif (k == 'is_vulnerable_to_ccs_injection'):
                            Dict_SSL_Vulns['CCS_INJECTION'] = Deep_Result[k]
                        elif (k == 'robot_result'):
                            Dict_SSL_Vulns['ROBOT'] = Deep_Result[k]
                        elif (k == 'is_vulnerable_to_client_renegotiation_dos'):
                            Dict_SSL_Vulns['CLIENT_RENEGOTIATION_DOS'] = Deep_Result[k]
                        elif (k == 'supports_secure_renegotiation'):
                            pass
                        else:
                            print (f'{k} : {Deep_Result[k]}')

                        if (TLS_Version != "" and Supported_Version != "" and Temp_Array_Ciphers == []):
                            print (f'{TLS_Version} : {Supported_Version}')
                            TLS_Version, Supported_Version = "",""
                        elif (TLS_Version != "" and Supported_Version != "" and Temp_Array_Ciphers != []):
                            print (f'{TLS_Version} : {Supported_Version}\n\n{Temp_Array_Ciphers}\n\n{Temp_Array_Ephemeral}')
                            TLS_Version, Supported_Version, Temp_Array_Ciphers, Temp_Array_Ephemeral = "","",[],[]

    return Dict_Full_SSL


#def SSL_Vulns_OLD(url, t_seconds, context = create_unverified_context(), Dict_SSL = {'Ciphers': [], 'TLS': [], 'Certificate': {}}):
#    def Check_SSL_Values(List_With_Keys, Temp_Key = ""):
#        Array_Temp = []
#        for i in List_With_Keys:
#            if ('@' in i): Temp_Key = i.split('@')[0]
#            else: Temp_Key = i
#            if (Temp_Key not in Array_SSH_Algorithms):
#                Array_Temp.append(Temp_Key)
#        return Array_Temp
#
#    def Check_Protocol(Ciphers):
#        if (Ciphers != "TLSv1.3" or Ciphers != "TLSv1.2"): return Ciphers
#        else: return Ciphers
#
#    if ('http://' in url): URL = url.split('http://')[1]
#    elif ('https://' in url): URL = url.split('https://')[1]
#
#    if (url.count(':') > 1): Port = url.split(':')[2]
#    else: Port = 443
#
#    try:
#        with create_connection((URL, int(Port)), timeout=t_seconds) as sock:
#            with context.wrap_socket(sock, server_hostname=URL) as ssock:
#                cert_der = ssock.getpeercert(True)
#                cert = x509.load_der_x509_certificate(cert_der, default_backend())
#
#                # Check_Ciphers
#                for Ciphers in ssock.shared_ciphers():
#                    for Algorithm in array(Array_TLS_Algorithms):
#                        if (Algorithm in Ciphers[0]):
#                            if (Array_TLS_Algorithms[0] in Ciphers[0]):
#                                if ("SHA256" in Ciphers[0] or "SHA512" in Ciphers[0]): Dict_SSL['Ciphers'].append(Ciphers[0])
#                                Dict_SSL['TLS'].append(Check_Protocol(Ciphers[1]))
#                                break
#                            else:
#                                Dict_SSL['Ciphers'].append(Ciphers[0])
#                                Dict_SSL['TLS'].append(Check_Protocol(Ciphers[1]))
#                                break
#        return Dict_SSL
#    except (ConnectionRefusedError, gaierror): Logs.Log_File(f'{strftime("%Y-%m-%d_%H:%M:%S")} - {url} - It was not possible to connect to the website\n')
#
