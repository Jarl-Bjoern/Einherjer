#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *
from ..Standard_Operations.Logs import Logs
from ..Standard_Operations.Colors import Colors

class Check_FTP:
    def FTP_Anonymous_Check(url, Host_Name, Dict_Temp = {}):
        if ('ftp://' in url):    URL = url.split('ftp://')[1]
        else:                    URL = url

        if (url.count(':') > 1): Port = url.split(':')[2]
        else:                    Port = 21

        if (Host_Name != ""):    Dict_Temp['DNS'] = Host_Name
        else:                    Dict_Temp['DNS'] = ""

        ftp = FTP()
        try:
            ftp.connect(URL, int(Port))
            msg    = ftp.login()
            Banner = ftp.getwelcome()
            if (str(Banner) != ""):
                Dict_Temp['Banner'] = str(Banner).split('220')[1][2:-1]

            if ("Login successful." in msg):
                Dict_Temp['Anonymous_Login'] = "True"
        except ConnectionRefusedError:
            print ("Error")

        print (Dict_Temp)

        return Dict_Temp

    def FTP_Brute_Force(url):
        pass

    def FTP_Password_Spray(url):
        pass
