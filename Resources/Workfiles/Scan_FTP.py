#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

def Check_FTP(url, Dict_Temp = {'DNS': "", 'Anonymous_Login': ""]):
    ftp = FTP()
    Host = "192.168.198.129"
    Port = 21
    try:
        ftp.connect(HOST, PORT)
        msg = ftp.login()
        Banner = ftp.getwelcome()
        if ("Login successful." in msg):
            Dict_Temp['Anonymous_Login'] = "True"
    except ConnectionRefusedError: pass

    return Dict_Temp
