#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from Resources.Header_Files.Variables import *
from Resources.Standard_Operations.Logs import Logs
from Resources.Colors import Colors

def Check_Certificate(url, t_seconds, Host_Name, context = create_unverified_context(), Counter_URL = 0, Dict_Temp = {}):
    if ('http://' in url): URL = url.split('http://')[1]
    elif ('https://' in url): URL = url.split('https://')[1]

    for _ in url:
       if (_ == ':'): Counter_URL += 1
    if (Counter_URL > 1): Port = url.split(':')[2]
    else: Port = 443

    if (Host_Name != ""): Dict_Temp['DNS'] = Host_Name
    else: Dict_Temp['DNS'] = ""

    try:
        with create_connection((URL, int(Port)), timeout=t_seconds) as sock:
            with context.wrap_socket(sock, server_hostname=URL) as ssock:
                cert_der = ssock.getpeercert(True)
                cert = x509.load_der_x509_certificate(cert_der, default_backend())

                Current_Date = datetime.now()
                Dict_Temp['Issuer'] = str(cert.issuer)
                Dict_Temp['Signature_Algorithm'] = str(cert.signature_hash_algorithm.name).upper()
                Dict_Temp['Signature_OID_Algorithm'] = str(cert.signature_algorithm_oid).upper()
                Dict_Temp['Cert_Creation_Date'] = str(cert.not_valid_before)
                Dict_Temp['Cert_EOL'] = str(cert.not_valid_after)
                Date_Block = str(cert.not_valid_after).split(' ')[0].split('-')
                Dict_Temp['Date_Difference'] = f'{(Current_Date - datetime(int(Date_Block[0]), int(Date_Block[1]), int(Date_Block[2]))).days} Days'
                Dict_Temp['Current_Date'] = str(Current_Date).split('.')[0]
        if (Host_Name != ""): Logs.Log_File(Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'+Colors.BLUE+'Certificate-Check\n'+Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'+Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - {Host_Name} - '+Colors.CYAN+'Certificate Information was succesfully recorded.\n\n')
        else: Logs.Log_File(Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'+Colors.BLUE+'Certificate-Check\n'+Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'+Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - '+Colors.CYAN+'Certificate Information was successfully recorded.\n\n')
    except (ConnectionRefusedError, gaierror): Logs.Write_Log(url, Host_Name)

    return Dict_Temp
