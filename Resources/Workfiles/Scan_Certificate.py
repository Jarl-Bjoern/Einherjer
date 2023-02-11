#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from Resources.Header_Files.Variables import *
from Resources.Standard_Operations.Logs import Logs
from Resources.Colors import Colors

def Check_Certificate(url, t_seconds, Host_Name, context = create_unverified_context(), Dict_Temp = {'DNS': "", 'Issuer': "", 'Subject': "", 'Signature_Algorithm': "", 'Cert_Creation_Date': "", 'Cert_EOL': "", 'Date_Difference': "", 'Current_Date': ""}):
    if ('https://' in url): URL = url.split('https://')[1]
    elif ('http://' in url): URL = url.split('http://')[1]
    else: URL = url

    if ('/' in URL):
        Temp = URL.split('/')[0]
        URL = Temp

    if (url.count(':') > 1): Port = url.split(':')[2]
    else: Port = 443

    if (Host_Name != ""): Dict_Temp['DNS'] = Host_Name
    else: Dict_Temp['DNS'] = ""

    try:
        with create_connection((URL, int(Port)), timeout=t_seconds) as sock:
            with context.wrap_socket(sock, server_hostname=URL) as ssock:
                cert_der = ssock.getpeercert(True)
                cert = load_der_x509_certificate(cert_der, default_backend())
                #cert_key = X509.load_cert_string(cert_der, X509.FORMAT_DER)

                Current_Date = datetime.now()
                #public_key = cert_key.get_pubkey()
                #rsa_key = public_key.get_rsa()
                #cipher = rsa_key.public_encrypt('plaintext', RSA.pkcs1_padding)
                for i in str(cert.subject):
                    print (i)
                Dict_Temp['Issuer'] = str(cert.issuer)
                Dict_Temp['Subject'] = str(cert.subject)
                Dict_Temp['Signature_Algorithm'] = str(cert.signature_algorithm_oid).split('name=')[1][:-2].upper()
                Dict_Temp['Cert_Creation_Date'] = str(cert.not_valid_before)
                Dict_Temp['Cert_EOL'] = str(cert.not_valid_after)
                Date_Block = str(cert.not_valid_after).split(' ')[0].split('-')
                Date_Difference = (Current_Date - datetime(int(Date_Block[0]), int(Date_Block[1]), int(Date_Block[2]))).days
                if (Date_Difference < 0): Dict_Temp['Date_Difference'] = f'{str(Date_Difference)[1:]} days before expires'
                else: Dict_Temp['Date_Difference'] = f'expired since {Date_Difference} days'
                Dict_Temp['Current_Date'] = str(Current_Date).split('.')[0]
        if (Host_Name != ""): Logs.Log_File(Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'+Colors.BLUE+'Certificate-Check\n'+Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'+Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {html_decode(url)} - {Host_Name} - '+Colors.CYAN+'Certificate Information was succesfully recorded.\n\n')
        else: Logs.Log_File(Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'+Colors.BLUE+'Certificate-Check\n'+Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'+Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {html_decode(url)} - '+Colors.CYAN+'Certificate Information was successfully recorded.\n\n')
    except (ConnectionRefusedError, gaierror): Logs.Write_Log(html_decode(url), Host_Name)

    if (Dict_Temp['Issuer'] == ""): Dict_Temp['Issuer'] = "FEHLT"
    if (Dict_Temp['Subject'] == ""): Dict_Temp['Subject'] = "FEHLT"
    if (Dict_Temp['Signature_Algorithm'] == ""): Dict_Temp['Signature_Algorithm'] = "FEHLT"
    if (Dict_Temp['Cert_Creation_Date'] == ""): Dict_Temp['Cert_Creation_Date'] = "FEHLT"
    if (Dict_Temp['Cert_EOL'] == ""): Dict_Temp['Cert_EOL'] = "FEHLT"
    if (Dict_Temp['Date_Difference'] == ""): Dict_Temp['Date_Difference'] = "FEHLT"
    if (Dict_Temp['Current_Date'] == ""): Dict_Temp['Current_Date'] = "FEHLT"

    return Dict_Temp
