#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *
from ..Standard_Operations.Logs import Logs
from ..Standard_Operations.Colors import Colors
from ..Standard_Operations.Standard import Standard

class Scan_DNS:
    def AXFR_Scan(Target, Hostname):
        Zones = from_xfr(xfr(Target, Hostname))
        Names = Zones.nodes.keys()
        Names.sort()
        for Name in Names:
            print(Zones[Name].to_text(Name))    

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
