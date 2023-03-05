#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *
from ..Standard_Operations.Logs import Logs
from ..Standard_Operations.Colors import Colors

def Check_HTTP_Methods(url, Host_Name, Dict_Temp = {'DNS': "", 'CONNECT': "", 'DELETE': "", 'HEAD': "", 'OPTIONS': "", 'PATCH': "", 'POST': "", 'PUT': "", 'TRACE': ""}, Switch_URL = False):
    if (Host_Name != ""): Dict_Temp['DNS'] = Host_Name
    else: Dict_Temp['DNS'] = ""

    async def Check_Methods():
        Limit = TCPConnector(limit_per_host=5)
        async with ClientSession(connector=Limit, trust_env=True) as s:
            for Method in Array_HTTP_Methods:
                try:
                    async with s.request(Method, url, ssl=False) as r:
                        if (str(r.status) == "200"):
                            Dict_Temp[Method] = "True"
                        else:
                            Dict_Temp[Method] = "False"
                except ServerDisconnectedError:
                    Dict_Temp[Method] = "False"

    asyncio.run(Check_Methods())

    if (Host_Name != ""): Logs.Log_File(Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'+Colors.BLUE+'HTTP-Methods-Check\n'+Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'+Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {html_decode(url)} - {Host_Name}'+Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'+Colors.ORANGE+'\nEinherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp}\n\n')
    else: Logs.Log_File(Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'+Colors.BLUE+'HTTP-Methods-Check\n'+Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'+Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {html_decode(url)}'+Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'+Colors.ORANGE+Colors.ORANGE+'\nEinherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp}\n\n')

    return Dict_Temp
