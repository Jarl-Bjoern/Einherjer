#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

class Check_SMTP:
    def Check_TLS(Target):
        Mail = SMTP(Target, 25)
        Mail.ehlo()
        try:
                Mail.starttls()
                Mail.ehlo()
        except SSLZeroReturnError:
            print ("Unencrypted")
        finally:
            try:
                Mail.quit()
            except SMTPServerDisconnected:
                pass

    def Test(Target):
        Mail = SMTP(Target, 25)
        Mail.docmd()
        Mail.quit()

    def Check_Open_Relay(Target, sender, receivers, message):
        Mail = SMTP(Target, 25)
        Mail.ehlo()
        Mail.sendmail(sender, receivers, message)
        Mail.quit()
