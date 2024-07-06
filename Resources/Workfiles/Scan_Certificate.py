#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables       import *
from ..Standard_Operations.Logs     import Logs
from ..Standard_Operations.Colors   import Colors
from ..Standard_Operations.Standard import Standard

def Check_Certificate(url, t_seconds, Host_Name, Location, context = create_unverified_context(), self_signed_check = create_default_context(), Dict_Temp = {}):
    if ('https://' in url):   URL = url.split('https://')[1]
    elif ('ssl://' in url):   URL = url.split('ssl://')[1]

    # Remove_Directories
    if ('/' in URL):
        Temp = URL.split('/')[0]
        URL  = Temp

    # Port_Filter
    if (url.count(':') > 1): Port = URL.split(':')[1]
    else:                    Port = 443

    # Get_Only_Target
    if (':' in URL):         Target = URL.split(':')[0]
    else:                    Target = URL

    # Get_Host_Name
    if (Host_Name != ""):    Dict_Temp['DNS'] = Host_Name
    else:                    Dict_Temp['DNS'] = ""

    # Check_Self_Signed_Certificate
    #try:
    #    with create_connection((Target, int(Port)), timeout=t_seconds) as sock:
    #        try:
    #            with self_signed_check.wrap_socket(sock, server_hostname=Target) as ssock:
    #                Dict_Temp['Self_Signed'] = False
    #        except SSLCertVerificationError:
    #            Dict_Temp['Self_Signed'] = True
    #except (ConnectionRefusedError, gaierror, SSLError, SSLZeroReturnError, TimeoutError):
    #    pass

    # Grab_Cert_Information
    try:
        with socket_create_connection((Target, int(Port)), timeout=t_seconds) as sock:
            try:
                with context.wrap_socket(sock, server_hostname=Target) as ssock:
                    # Cert_Connect_And_Collect
                    try:
                        cert_der = ssock.getpeercert(binary_form=True)
                    except (ConnectionRefusedError, gaierror, SSLError, SSLZeroReturnError, TimeoutError):
                        Logs.Write_Log(url, Host_Name, join(Location, 'Logs'))

                    try:
                        cert = load_der_x509_certificate(cert_der, default_backend())
                    except TypeError:
                        cert_der = ssock.getpeercert(binary_form=False)
                        cert = load_der_x509_certificate(cert_der, default_backend())

                    # Get_Cert_Information
                    Current_Date = datetime.now()

                    Dict_Temp['Issuer']              = str(cert.issuer)[6:-2]
                    Dict_Temp['Subject']             = str(cert.subject)[6:-2]
                    Dict_Temp['Signature_Algorithm'] = str(cert.signature_algorithm_oid).split('name=')[1][:-2].upper()
                    Dict_Temp['Public_Key']          = resplit('<| ', str(cert.public_key()))[1].split('.')[::-1][0]
                    Dict_Temp['Cert_Creation_Date']  = str(cert.not_valid_before)
                    Dict_Temp['Cert_EOL']            = str(cert.not_valid_after)

                    # Cert_Expire_Filter
                    Date_Block = str(cert.not_valid_after).split(' ')[0].split('-')
                    Date_Difference = (Current_Date - datetime(int(Date_Block[0]), int(Date_Block[1]), int(Date_Block[2]))).days
                    if (Date_Difference < 0): Dict_Temp['Date_Difference'] = f'{str(Date_Difference)[1:]} days before expires'
                    else:                     Dict_Temp['Date_Difference'] = f'expired since {Date_Difference} days'

                    # Add_Scan_Date
                    Dict_Temp['Current_Date'] = str(Current_Date).split('.')[0]

                    # Logging
                    if (Host_Name != ""):
                        Logs.Log_File(
                            Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                            +Colors.BLUE+'Certificate-Check\n'
                            +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                            +Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - {Host_Name} - '+Colors.CYAN
                            +'Certificate Information was succesfully recorded.\n\n',
                            join(Location, 'Logs')
                        )
                        Standard.Write_Output_File('affected_certificate_targets.txt', f'{url} ({Host_Name})', Location)
                    else:
                        Logs.Log_File(
                            Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                            +Colors.BLUE+'Certificate-Check\n'
                            +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                            +Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - '
                            +Colors.CYAN+'Certificate Information was successfully recorded.\n\n',
                            join(Location, 'Logs')
                        )
                        Standard.Write_Output_File('affected_certificate_targets.txt', f'{url} (-)', Location)

            except (ConnectionRefusedError, gaierror, SSLError, SSLZeroReturnError, TimeoutError):
                Logs.Write_Log(url, Host_Name, join(Location, 'Logs'))
            except:
                pass

    except (ConnectionRefusedError, gaierror, SSLError, SSLZeroReturnError, TimeoutError):
        Logs.Write_Log(url, Host_Name, join(Location, 'Logs'))

    return Dict_Temp
