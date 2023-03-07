#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

class Check_SMTP:
    def Check_Arguments(Target):
        Mail = SMTP(Target, 25)
        Output = Mail.docmd('ehlo all')
        print (str(Output[1]).split(r'\n'))
        Mail.quit()

    def Check_Open_Relay(Target, sender, receivers, message):
        Mail = SMTP(Target, 25)
        Mail.ehlo()
        Mail.sendmail(sender, receivers, message)
        Mail.quit()

    def Check_TLS(Target):
        Mail = SMTP(Target, 25)
        Output = Mail.docmd('ehlo all')
        if ('starttls' in str(Output[1]) or 'STARTTLS' in str(Output[1])):
            TLS_Output = Mail.docmd('starttls')
            if ('Ready to start TLS' in str(TLS_Output[1])):
                print ("Passt")
        Mail.quit()
