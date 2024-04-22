#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def JSON_Table(Dict_Result, location, Array_Files = []):
    def Write_JSON(keyword, location, result_file):
        with open(join(location, result_file), 'w', encoding='UTF-8') as f:
            json_dumps(Dict_Result[keyword], f)

    # Certificates
    if (Dict_Result['Certificate'] != {}):
        Array_Files.append(join(location, 'result_certificate.json'))
        Write_JSON('Certificate', location, 'result_certificate.json')

    # Cookie_Flags
    if (Dict_Result['Security_Flag'] != {}):
        Array_Files.append(join(location, 'result_security_flags.json'))
        Write_JSON('Security_Flag', location, 'result_security_flags.json')

    # FTP
    if (Dict_Result['FTP'] != {}):
        Array_Files.append(join(location, 'result_ftp.json'))
        Write_JSON('FTP', location, 'result_ftp.json')

    # HTTP_Header
    if (Dict_Result['Header'] != {}):
        Array_Files.append(join(location, 'result_header.json'))
        Write_JSON('Header', location, 'result_header.json')

    # HTTP_Information_Disclosure
    if (Dict_Result['Information'] != {}):
        Array_Files.append(join(location, 'result_information_disclosure.json'))
        Write_JSON('Information', location, 'result_information_disclosure.json')

    # SSH
    if (Dict_Result['SSH'] != {}):
        Array_Files.append(join(location, 'result_ssh_vulns.json'))
        Write_JSON('SSH', location, 'result_ssh_vulns.json')

    # SSL
    if (Dict_Result['SSL'] != {}):
        Array_Files.append(join(location, 'result_ssl.json'))
        Write_JSON('SSL', location, 'result_ssl.json')       

    return Array_Files
