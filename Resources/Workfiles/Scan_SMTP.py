#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *
from ..Standard_Operations.Logs import Logs
from ..Standard_Operations.Colors import Colors

class Check_SMTP:
    def Check_Arguments(url, Array_Temp = []):
        if   (url.count(':') == 2):  Target, Port = url.split('smtp://')[1].split(':')
        elif (url.count(':') == 1):  Target, Port = url.split('smtp://')[1], 25

        Mail   = SMTP(Target, int(Port))
        Output = Mail.docmd('ehlo all')
        for _ in str(Output[1]).split(r'\n'):
            if   ("b'" in _):   Array_Temp.append(_[2:])
            elif ("'"  in _):   Array_Temp.append(_[:-1])
            else:               Array_Temp.append(_)
        Mail.quit()

        return Array_Temp

    def Check_Open_Relay(url, sender, receiver, message):
        if   (url.count(':') == 2):  Target, Port = url.split('smtp://')[1].split(':')
        elif (url.count(':') == 1):  Target, Port = url.split('smtp://')[1], 25

        Mail = SMTP(Target, int(Port))
        Mail.docmd('ehlo all')
        Output = Mail.docmd(f'mail from:{sender}')
        if ('ok' in str(Output[1]).lower()):
            Output = Mail.docmd(f'rcpt to:{receiver}')
            if ('ok' in str(Output[1]).lower()):
                Output = Mail.docmd(message)
            elif('not permitted' in str(Output[1]).lower() or
                 'access denied' in str(Output[1]).lower()):
                    print ("FAIL")
        Mail.quit()

    def Check_TLS(url):
        if   (url.count(':') == 2):  Target, Port = url.split('smtp://')[1].split(':')
        elif (url.count(':') == 1):  Target, Port = url.split('smtp://')[1], 25

        Mail   = SMTP(Target, int(Port))
        Output = Mail.docmd('ehlo all')
        if ('starttls' in str(Output[1]).lower()):
            TLS_Output = Mail.docmd('starttls')
            if ('Ready to start TLS' in str(TLS_Output[1])):
                print ("OK")
            else:
                print ("Unencrypted!")
        Mail.quit()
