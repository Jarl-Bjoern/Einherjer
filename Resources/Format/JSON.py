#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def JSON_Table(Dict_Result, location):
    try: import json
    except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")

    def Write_JSON(keyword, location, result_file):
        with open(join(location, result_file), 'w', encoding='UTF-8') as f:
            json.dump(Dict_Result[keyword], f)

    if (Dict_Header['Header'] != {}):
        Array_Files.append(join(location, 'result_header.json'))
        Write_JSON('Header', location, 'result_header.json')
    if (Dict_Header['Information'] != {}):
        Array_Files.append(join(location, 'result_information_disclosure.json'))
        Write_JSON('Information', location, 'result_information_disclosure.json')
    if (Dict_Header['SSH'] != {}):
        Array_Files.append(join(location, 'result_ssh_vulns.json'))
        Write_JSON('SSH', location, 'result_ssh_vulns.json')
    if (Dict_Header['Security_Flag'] != {}):
        Array_Files.append(join(location, 'result_security_flags.json'))
        Write_JSON('Security_Flag', location, 'result_security_flags.json')
    if (Dict_Header['Certificate'] != {}):
        Array_Files.append(join(location, 'result_certificate.json'))
        Write_JSON('Header', location, 'result_certificate.json')
