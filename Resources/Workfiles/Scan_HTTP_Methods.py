#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *
from ..Standard_Operations.Logs import Logs
from ..Standard_Operations.Colors import Colors

def Check_HTTP_Methods(url, t_seconds, Host_Name, Dict_Temp = {'DNS': "", 'CONNECT': "", 'DELETE': "", 'HEAD': "", 'OPTIONS': "", 'PATCH': "", 'POST': "", 'PUT': "", 'TRACE': ""}, Switch_URL = False):
    from requests import request
    for Method in Array_HTTP_Methods:
        try:
            r = request(Method, url, timeout=2.5)
            if ("200" in str(res)):
                print(res)
        except (ConnectionError, ProtocolError, RemoteDisconnected):
            print ("Error")
        sleep(0.25)

#
#
#    if ('https://' in url):
#        URL = url.split('https://')[1]
#        Switch_URL = True
#    elif ('http://' in url): URL = url.split('http://')[1]
#    else: URL = url
#
#    if ('/' in URL):
#        Temp = URL.split('/')[0]
#        URL = Temp
#
#    if (url.count(':') > 1): Port = url.split(':')[2]
#    else: Port = 443
#
#    if (Host_Name != ""): Dict_Temp['DNS'] = Host_Name
#    else: Dict_Temp['DNS'] = ""
#
#    if (Switch_URL == True):
#        try: r = HTTPSConnection(URL, port=Port, timeout=15)
#        except TimeoutError: pass
#    else:
#        try: r = HTTPConnection(URL, port=Port, timeout=15)
#        except TimeoutError: pass        
#    
#    for Method in Array_HTTP_Methods:
#        try:
#            r.request(Method, "/")
#            res = r.getresponse()
#            if (res.status == "200" and res.reason == "OK"):
#                print(res.status, res.reason)
#            sleep(0.25)
#        except TimeoutError: pass

    return Dict_Temp
