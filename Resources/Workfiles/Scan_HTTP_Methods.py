#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *
from ..Standard_Operations.Logs import Logs
from ..Standard_Operations.Colors import Colors

def Check_HTTP_Methods(url, Host_Name, Dict_Temp = {'DNS': "", 'CONNECT': "", 'DELETE': "", 'HEAD': "", 'OPTIONS': "", 'PATCH': "", 'POST': "", 'PUT': "", 'TRACE': ""}, Switch_URL = False):
    async def Check_Methods():
        async with ClientSession() as s:
            for Method in Array_HTTP_Methods:
                try:
                    async with s.request(Method, url) as r:
                        if (str(r.status) == "200"):
                            Dict_Temp[Method] = "True"
                except ServerDisconnectedError:
                    Dict_Temp[Method] = "False"

    asyncio.run(Check_Methods())

    return Dict_Temp
