#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *
from ..Standard_Operations.Logs import Logs
from ..Standard_Operations.Colors import Colors

class Check_FTP:
    def FTP_Anonymous_Check(url, Host_Name, Location, Dict_Temp = {}):
        if ('ftp://' in url):    URL = url.split('ftp://')[1]
        else:                    URL = url

        if (url.count(':') > 1): Target, Port = URL.split(':')
        else:                    Target, Port = URL, 21

        if (Host_Name != ""):    Dict_Temp['DNS'] = Host_Name
        else:                    Dict_Temp['DNS'] = ""

        with FTP() as ftp:
            try:
                ftp.connect(Target, int(Port))
                msg    = ftp.login()
                Banner = ftp.getwelcome()
                if (str(Banner) != ""):
                    Dict_Temp['Banner'] = str(Banner).split('220')[1][2:-1]

                if ("Login successful." in msg):
                    Dict_Temp['Anonymous_Login'] = "True"

                # Logging
                if (Host_Name != ""):
                    Logs.Log_File(
                        Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                        +Colors.BLUE+'FTP-Check\n'
                        +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                        +Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - {Host_Name}'
                        +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
                        +Colors.ORANGE+'\nEinherjer Output'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp}\n\n',
                        join(Location, 'Logs')
                    )
                else:
                    Logs.Log_File(
                        Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                        +Colors.BLUE+'FTP-Check\n'
                        +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                        +Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url}'
                        +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
                        +Colors.ORANGE+'\nEinherjer Output'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp}\n\n',
                        join(Location, 'Logs')
                    )

            except ConnectionRefusedError:
                pass

        return Dict_Temp

    def FTP_Brute_Force(url):
        pass

    def FTP_Password_Spray(url):
        pass
