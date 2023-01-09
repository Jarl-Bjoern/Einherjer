#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from Resources.Colors import Colors
from Resources.Header_Files.Libraries import Date, dirname, exists, makedirs, realpath, sleep

class Logs:
    def Error_Message(x):
        print(x), sleep(2), exit()

    def Write_Log(url, host, Log_Path = dirname(realpath(__file__)).replace('Resources/Header_Files', 'Logs')):
        if (not exists(Log_Path)): makedirs(Log_Path)
        with open(join(Log_Path, f'{Date}_failed-url.txt'), 'a') as f:
            f.write(f'{url}\n')
        if (host != ""): Logs.Log_File(Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - '+Colors.RED+'FAILED\n'+Colors.RESET)
        else: Logs.Log_File(Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - '+Colors.RED+'FAILED\n'+Colors.RESET)

    def Log_File(Text, Log_Path = dirname(realpath(__file__)).replace('Resources/Header_Files', 'Logs')):
        if (not exists(Log_Path)): makedirs(Log_Path)
        with open(join(Log_Path, f"{Date}.log"), "a") as f:
            f.write(Text)
