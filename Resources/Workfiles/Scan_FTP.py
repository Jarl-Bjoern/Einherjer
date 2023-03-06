#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

def Check_FTP(url):
    ftp = FTP(url, port=22, timeout=15)
    ftp.login()
    
    return Dict_Temp
