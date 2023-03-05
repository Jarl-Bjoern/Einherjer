#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *
from ..Standard_Operations.Logs import Logs
from ..Standard_Operations.Colors import Colors

def Check_HTTP_Methods(url, t_seconds, Host_Name, Dict_Temp = {'DNS': "", 'CONNECT': "", 'DELETE': "", 'HEAD': "", 'OPTIONS': "", 'PATCH': "", 'POST': "", 'PUT': "", 'TRACE': ""}):
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

    r = HTTPSConnection(URL)

    for Method in Array_HTTP_Methods:
        r.request(Method, "/")
        res = r.getresponse()
        if (res.status == "200" and res.reason == "OK"):
            print(res.status, res.reason)
        sleep(0.25)

    return Dict_Temp
