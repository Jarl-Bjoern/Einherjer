#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *
from ..Standard_Operations.Logs import Logs
from ..Standard_Operations.Colors import Colors
from ..Standard_Operations.Standard import Standard

def Check_HTTP_Methods(url, Host_Name, Dict_Proxies, Dict_Auth, Location, Dict_Temp = {}, Switch_URL = False):
    # Get_Host_Name
    if (Host_Name != ""): Dict_Temp['DNS'] = Host_Name
    else:                 Dict_Temp['DNS'] = ""

    # Function
    async def Check_Methods():
        Limit = TCPConnector(limit_per_host=5)

        async with ClientSession(connector=Limit, trust_env=True) as s:
            for Method in Array_HTTP_Methods:
                try:
                    # Basic_Auth_With_Proxy
                    if (Dict_Proxies['http'] != '' and Dict_Auth['user'] != ''):
                        async with s.request(Method, url, ssl=False, auth=BasicAuth(Dict_Auth['user'], Dict_Auth['password']), proxy=Dict_Proxies['http']) as r:
                            if (str(r.status) == "200"):
                                Dict_Temp[Method] = "True"
                            else:
                                Dict_Temp[Method] = "FEHLT"

                    # Basic_Auth
                    elif (Dict_Proxies['http'] == '' and Dict_Auth['user'] != ''):
                        async with s.request(Method, url, ssl=False, auth=BasicAuth(Dict_Auth['user'], Dict_Auth['password'])) as r:
                            if (str(r.status) == "200"):
                                Dict_Temp[Method] = "True"
                            else:
                                Dict_Temp[Method] = "FEHLT"

                    # Proxy
                    elif (Dict_Proxies['http'] != '' and Dict_Auth['user'] == ''):
                          async with s.request(Method, url, ssl=False, proxy=Dict_Proxies['http']) as r:
                            if (str(r.status) == "200"):
                                Dict_Temp[Method] = "True"
                            else:
                                Dict_Temp[Method] = "FEHLT"

                    # Nothing
                    elif (Dict_Proxies['http'] == '' and Dict_Auth['user'] == ''):
                        async with s.request(Method, url, ssl=False) as r:
                            if (str(r.status) == "200"):
                                Dict_Temp[Method] = "True"
                            else:
                                Dict_Temp[Method] = "FEHLT"
                except (ClientConnectorError, ServerDisconnectedError):
                    Dict_Temp[Method] = "FEHLT"

    # Start_Scan
    asyncio.run(Check_Methods())

    # Logging
    if (Host_Name != ""):
        Logs.Log_File(
            Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
            +Colors.BLUE+'HTTP-Methods-Check\n'
            +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
            +Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - {Host_Name}'
            +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
            +Colors.ORANGE+'\nEinherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp}\n\n',
            join(Location, 'Logs')
        )
    else:
        Logs.Log_File(
            Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
            +Colors.BLUE+'HTTP-Methods-Check\n'
            +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
            +Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url}'
            +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
            +Colors.ORANGE+Colors.ORANGE+'\nEinherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp}\n\n',
            join(Location, 'Logs')
        )

    # Write_Output
    if (Host_Name == ""):
        Standard.Write_Output_File('affected_http_methods_targets.txt', f'{url} (-)', Location)
    else:
        Standard.Write_Output_File('affected_http_methods_targets.txt', f'{url} ({Host_Name})', Location)

    return Dict_Temp
