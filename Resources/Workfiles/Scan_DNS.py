#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

def Scan_DNS():
    def Test():
          try:
              Temp = gethostbyname(Target)
              if (Temp == Target): Temp = ""
          except (gaierror, herror): pass

    def DNS_Fuzz(domain, Array_Temp = [], Array_Result = []):
        for _ in Wordlist:
            url = f'{_}.{domain}'
            r = get(url)
            if (r.status_code == "200"):
                if (url not in Array_Temp):
                    Array_Temp.append(url)
                    Array_Result.append(url)
        return Array_Temp, Array_Result

    Array_Temp, Array_Result = DNS_Fuzz("test.localdomain")
    while True:
      if (len(Array_Temp) != 0):
          for _ in Array_Temp:
              Array_Temp_Sec, Array_Result = DNS_Fuzz(_)
      else:
          break
      Array_Temp = Array_Temp_Sec
