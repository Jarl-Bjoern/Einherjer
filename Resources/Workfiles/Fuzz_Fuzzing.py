#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *
from ..Standard_Operations.Logs import Logs
from ..Standard_Operations.Colors import Colors

def Check_Site_Paths(url, t_seconds, Host_Name, array_wordlists, Location, Dict_Result = {"200": [], "204": [], "301": [], "302": [], "307": [], "308": [], "401": [], "403": [], "405": [], "500": []}, Array_Temp = [], Array_Status_Code = ["200", "204", "301", "302", "307", "308", "401", "403", "405", "500"]):
    async def Check_Fuzz(url):
        Limit, Client_Timeout = TCPConnector(limit_per_host=100), ClientTimeout(total=30)
        Client_Headers = {'Connection': 'close'}
        async with ClientSession(connector=Limit, trust_env=True, headers=Client_Headers) as s:
            # Get_Protocol
            if ('http://' in url):
                Protocol, Begin =  'http://', 7
            elif ('https://' in url):
                Protocol, Begin = 'https://', 8

            for Word in array(array_wordlists):
                # Convert_With_URL_Encoding
                if (url.count('/') >= 3 and '//' in url):
                    Temp_URL_Switcher = url_encode(url[Begin:])
                    url               = f'{Protocol}{Temp_URL_Switcher.replace("2%F", "/")}'
                elif (url.count('/') == 2 and '//' in url):
                    pass

                # Generate_URL_Encoded_Word
                URL = f'{url}/{url_encode(Word).replace("2%F", "/")}'

                # Start_Fuzz
                async with s.get(url_encode(URL), ssl=False, timeout=Client_Timeout) as r:
                    if (str(r.status) in Array_Status_Code):
                        if (URL not in Array_Temp):
                            Array_Temp.append(URL)
                            Dict_Result[str(r.status)].append(URL)
                    await asyncio.sleep(t_seconds)

    # Start_Scan
    try:
        asyncio.run(Check_Fuzz(url))
    except asyncio.TimeoutError:
        Logs.Write_Log(url, Host_Name, join(Location, 'Logs'))

    return Array_Temp
