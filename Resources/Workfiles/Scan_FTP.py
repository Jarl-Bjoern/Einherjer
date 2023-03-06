#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

def Check_FTP(url, Dict_Temp = {'DNS': "", 'Anonymous_Login': ""]):
    if ('ftp://' in url): URL = url.split('ftp://')[1]
    else: URL = url

    if (url.count(':') > 1): Port = url.split(':')[2]
    else: Port = 21

    if (Host_Name != ""): Dict_Temp['DNS'] = Host_Name
    else: Dict_Temp['DNS'] = ""

    ftp = FTP()
    try:
        ftp.connect(URL, Port)
        msg = ftp.login()
        Banner = ftp.getwelcome()
        if ("Login successful." in msg):
            Dict_Temp['Anonymous_Login'] = "True"
    except ConnectionRefusedError: pass

    return Dict_Temp
