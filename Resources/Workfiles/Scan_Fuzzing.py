#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

def Check_Site_Paths(url, t_seconds, array_wordlists, Array_Temp = [], Array_Status_Code = ["200", "204", "301", "302", "307", "308", "401", "403", "405", "500"]):
    for Word in array_wordlists:
        URL = f'{url}/{Word}'
        r = get(URL, timeout=t_seconds, verify=False, allow_redirects=True)
        if (str(r.status_code) in Array_Status_Code):
            if (URL not in Array_Temp): Array_Temp.append(URL)
        sleep(t_seconds)

    return Array_Temp
