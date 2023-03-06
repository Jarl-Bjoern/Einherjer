#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

def Check_FTP(url, Dict_Temp = {'DNS': "", 'Anonymous_Login': ""]):
    ftp = FTP(url, port=22, timeout=15)
    msg = ftp.login()
    if ("Login successful." in msg):
        Dict_Temp['Anonymous_Login'] = "True"

    return Dict_Temp
