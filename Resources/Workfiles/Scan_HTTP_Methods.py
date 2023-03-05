#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *
from ..Standard_Operations.Logs import Logs
from ..Standard_Operations.Colors import Colors

def Check_HTTP_Methods(url, t_seconds, Host_Name, Dict_Temp = {'DNS': "", 'CONNECT': "", 'DELETE': "", 'HEAD': "", 'OPTIONS': "", 'PATCH': "", 'POST': "", 'PUT': "", 'TRACE': ""}):
    r = HTTPSConnection(url)
    for Method in Array_HTTP_Methods:
        r.request(Method, "/")
        res = r.getresponse()
        if (res.status == "200" and res.reason == "OK"):
            print(res.status, res.reason)
    
    return Dict_Temp
