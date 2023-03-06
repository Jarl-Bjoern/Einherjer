#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

def Check_Site_Paths(url, t_seconds, array_wordlists, Array_Temp = [], Array_Status_Code = ["200", "204", "301", "302", "307", "308", "401", "403", "405", "500"]):
    async def Check_Fuzz():
        Limit = TCPConnector(limit_per_host=100)
        async with ClientSession(connector=Limit, trust_env=True) as s:
            for Word in array_wordlists:
                URL = f'{url}/{Word}'
                async with s.get(url, ssl=False) as r:
                    if (str(r.status) in Array_Status_Code):
                        if (URL not in Array_Temp): Array_Temp.append(URL)
                    sleep(t_seconds)

    asyncio.run(Check_Fuzz())

    return Array_Temp
