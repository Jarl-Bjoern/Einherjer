#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *
from ..Standard_Operations.Logs import Logs
from ..Standard_Operations.Colors import Colors

def Check_HTTP_Methods(url, Host_Name, Dict_Proxies, Dict_Auth, file_format, Location, Dict_Temp = {'DNS': "", 'CONNECT': "", 'DELETE': "", 'HEAD': "", 'OPTIONS': "", 'PATCH': "", 'POST': "", 'PUT': "", 'TRACE': ""}, Switch_URL = False):
    if (Host_Name != ""): Dict_Temp['DNS'] = Host_Name
    else: Dict_Temp['DNS'] = ""

    async def Check_Methods():
        Limit = TCPConnector(limit_per_host=5)

        async with ClientSession(connector=Limit, trust_env=True) as s:
            for Method in Array_HTTP_Methods:
                try:
                    # Basic_Auth_With_Proxy
                    if (Dict_Proxies['http'] != '' and Dict_Auth['user'] != ''):
                        async with s.request(Method, url, ssl=False, auth=BasicAuth(Dict_Auth['user'], Dict_Auth['password']), proxy=Dict_Proxies['http']) as r:
                            if (str(r.status) == "200"):
                                Dict_Temp[Method] = "True"
                            else:
                                Dict_Temp[Method] = "FEHLT"

                    # Basic_Auth
                    elif (Dict_Proxies['http'] == '' and Dict_Auth['user'] != ''):
                        async with s.request(Method, url, ssl=False, auth=BasicAuth(Dict_Auth['user'], Dict_Auth['password'])) as r:
                            if (str(r.status) == "200"):
                                Dict_Temp[Method] = "True"
                            else:
                                Dict_Temp[Method] = "FEHLT"

                    # Proxy
                    elif (Dict_Proxies['http'] != '' and Dict_Auth['user'] == ''):
                          async with s.request(Method, url, ssl=False, proxy=Dict_Proxies['http']) as r:
                            if (str(r.status) == "200"):
                                Dict_Temp[Method] = "True"
                            else:
                                Dict_Temp[Method] = "FEHLT"

                    # Nothing
                    elif (Dict_Proxies['http'] == '' and Dict_Auth['user'] == ''):
                        async with s.request(Method, url, ssl=False) as r:
                            if (str(r.status) == "200"):
                                Dict_Temp[Method] = "True"
                            else:
                                Dict_Temp[Method] = "FEHLT"
                except ServerDisconnectedError:
                    Dict_Temp[Method] = "FEHLT"

    asyncio.run(Check_Methods())

    if (Host_Name != ""):
        Logs.Log_File(
            Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
            +Colors.BLUE+'HTTP-Methods-Check\n'
            +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
            +Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - {Host_Name}'
            +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
            +Colors.ORANGE+'\nEinherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp}\n\n'
        )
    else:
        Logs.Log_File(
            Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
            +Colors.BLUE+'HTTP-Methods-Check\n'
            +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
            +Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url}'
            +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
            +Colors.ORANGE+Colors.ORANGE+'\nEinherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp}\n\n'
        )

    # Format_Filtering
    if ("csv" in file_format):
        from ..Format.CSV import CSV_Table
        Array_Output = CSV_Table(Dict_Temp, Location)
    elif ("docx" in file_format):
        from ..Format.Word import Word_Table
        Array_Output = Word_Table(Dict_Temp, Location)
    elif ("html" in file_format):
        from ..Format.HTML import HTML_Table
        Array_Output = HTML_Table(Dict_Temp, Location)
    elif ("json" in file_format):
        from ..Format.JSON import JSON_Table
        Array_Output = JSON_Table(Dict_Temp, Location)
    elif ("md" in file_format):
        from ..Format.Markdown import Markdown_Table
        Array_Output = Markdown_Table(Dict_Temp, Location)
    elif ("pdf" in file_format):
        from ..Format.PDF import Create_PDF
        Array_Output = Word_Table(Dict_Temp, Location)
        if (osname == 'nt'): Create_PDF(Location)
        else: print("At this point it's not be possible to convert a docx file into a pdf under linux.\nPlease try it under windows.\n")
    elif ("tex" in file_format):
        from ..Format.LaTeX import Latex_Table
        Array_Output = Latex_Table(Dict_Temp, Location)
    elif ("xlsx" in file_format):
        from ..Format.Excel import Excel_Table
        Array_Output = Excel_Table(Dict_Temp, Location)
    elif ("xml" in file_format):
        from ..Format.XML import XML_Table
        #Array_Output = XML_Table(Dict_Temp, Location)
    elif ("yaml" in file_format):
        from ..Format.YAML import YAML_Table
        #Array_Output = YAML_Table(Dict_Temp, Location)

    return Dict_Temp
