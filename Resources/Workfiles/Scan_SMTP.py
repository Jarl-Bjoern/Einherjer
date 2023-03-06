#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

class Check_SMTP:
    def Check_TLS():
        Mail = SMTP(Target, 25)
        Mail.ehlo()
        Mail.starttls()
        Mail.ehlo()
        Mail.quit()

    def Test():
        Mail = SMTP(Target, 25)
        Mail.docmd()
        Mail.quit()

    def Check_Open_Relay(Target, sender, receivers, message):
        Mail = SMTP(Target, 25)
        Mail.ehlo()
        Mail.sendmail(sender, receivers, message)         
        Mail.quit()
