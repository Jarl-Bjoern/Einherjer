#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *
from ..Standard_Operations.Logs import Logs
from ..Standard_Operations.Colors import Colors
from ..Standard_Operations.Standard import Standard

def Check_Site_Paths(url, t_seconds, Host_Name, array_wordlists, Location, Dict_Result = {"200": [], "204": [], "301": [], "302": [], "307": [], "308": [], "401": [], "403": [], "405": [], "500": []}, Array_Temp = [], Array_Status_Code = ["200", "204", "301", "302", "307", "308", "401", "403", "405", "500"]):
    async def Check_Fuzz(url):
        Limit, Client_Timeout = TCPConnector(limit_per_host=100), ClientTimeout(total=30)
        Client_Headers = {'Connection': 'close'}
        async with ClientSession(connector=Limit, trust_env=True, headers=Client_Headers) as s:
            # Get_Protocol
            if ('http://' in url):
                Protocol, Begin =  'http://', 7
            elif ('https://' in url):
                Protocol, Begin = 'https://', 8

            # Filter_Wordlist
            if (type(array_wordlists) == str):
                with open(array_wordlists, 'r', encoding='latin-1') as f:
                    Array_Wordlist = f.read().splitlines()
            elif (type(array_wordlists) == list):
                for _ in listdir(array_wordlists):
                    Array_Temp_Wordlist = []
                    with open(array_wordlists, 'r', encoding='latin-1') as f:
                        Array_Temp_Wordlist = f.read().splitlines()
                    for Word in np_array(Array_Temp_Wordlist):
                        if (Word not in Array_Wordlist):
                            Array_Wordlist.append(Word)

            # Encode_The_Words
            n = 0
            for Word in np_array(Array_Wordlist):
                # Convert_With_URL_Encoding
                if (url.count('/') >= 3 and '//' in url):
                    Temp_URL_Switcher = url_encode(url[Begin:])
                    url               = f'{Protocol}{Temp_URL_Switcher.replace("2%F", "/")}'
                elif (url.count('/') == 2 and '//' in url):
                    pass

                # Generate_URL_Encoded_Word
                URL = f'{url}/{url_encode(Word).replace("2%F", "/")}'

                # Start_Fuzz
                async with s.get(URL, ssl=False, timeout=Client_Timeout) as r:
                    # Counter
                    if (n == 20):
                        if (osname == 'nt'): system('cls'), Standard.Print_Header()
                        else:                system('clear'), Standard.Print_Header()
                        n = 0
                    else:
                        n += 1

                    # Fuzzing_Progress
                    print (Colors.ORANGE+f'{r.status}'+Colors.RED+' - '+Colors.CYAN+f'{URL}'+Colors.RESET)
                    if (str(r.status) in Array_Status_Code):    
                        if (URL not in Array_Temp):
                            Array_Temp.append(URL)
                            Dict_Result[str(r.status)].append(URL)
                    await asyncio.sleep(0.075)

    # Start_Scan
    try:
        asyncio.run(Check_Fuzz(url))
    except asyncio.TimeoutError:
        Logs.Write_Log(url, Host_Name, join(Location, 'Logs'))

    return Array_Temp
