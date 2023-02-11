#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

class Check_SMTP:
    def Check_TLS():
        pass

    def Check_Open_Relay(Target, sender, receivers, message):
        Mail = smtplib.SMTP(Target,25)
        Mail.sendmail(sender, receivers, message)         
        Mail.quit()
