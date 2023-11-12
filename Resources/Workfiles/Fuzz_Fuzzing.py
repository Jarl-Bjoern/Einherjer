#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *
from ..Standard_Operations.Logs import Logs
from ..Standard_Operations.Colors import Colors

def Check_Site_Paths(url, t_seconds, array_wordlists, Dict_Result = {"200": [], "204": [], "301": [], "302": [], "307": [], "308": [], "401": [], "403": [], "405": [], "500": []}, Array_Temp = [], Array_Status_Code = ["200", "204", "301", "302", "307", "308", "401", "403", "405", "500"]):
    async def Check_Fuzz(url):
        Limit = TCPConnector(limit_per_host=100)
        async with ClientSession(connector=Limit, trust_env=True) as s:
            for Word in array(array_wordlists):
                URL = f'{url}/{Word}'
                async with s.get(html_encode(URL), ssl=False) as r:
                    if (str(r.status) in Array_Status_Code):
                        if (URL not in Array_Temp):
                            Array_Temp.append(html_encode(URL))
                            Dict_Result[str(r.status)].append(URL)
                    await asyncio.sleep(t_seconds)

    # Start_Scan
    try:
        asyncio.run(Check_Fuzz(url))
    except asyncio.TimeoutError:
        Logs.Write_Log(url, Host_Name, join(Location, 'Logs'))

    return Array_Temp
