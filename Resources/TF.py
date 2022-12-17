def Thread_Scanning_Start(url, t_seconds, queue, driver_options, scan_ssl, scan_header, scan_fuzzing, scan_ssh, scan_fuzzing_recurse, scan_security_flag, Count_Double_Point = 0, Host_Name = "", Target = ""):
    global Kill_Command

    while (Kill_Command != True):
            try:
                Dict_Result = queue.get()
                if (driver_options != None and '//' in url and 'http' in url): Take_Screenshot(driver, url)
                if (scan_header != False and '//' in url and 'http' in url):
                    Dict_Temp_Header, Dict_Temp_Information_Disclosure = {},{}
                    try:
                        r = get(url, timeout=(t_seconds, t_seconds), verify=False, allow_redirects=True)
                        # Host_Name_Filtering
                        if ('//' in url):
                            for i in range(0, len(url)):
                                if (url[i] == ":"): Count_Double_Point += 1
                            if (Count_Double_Point == 2): Host_Name = Get_Host_Name(url.split('//')[1].split(':')[0])
                            else: Host_Name = Get_Host_Name(url.split('//')[1])
                        else: Host_Name = Get_Host_Name(url)
                        if (Host_Name != ""):
                            Dict_Temp_Header['DNS'], Dict_Temp_Information_Disclosure['DNS'] = Host_Name[0], Host_Name[0]
                        else: Dict_Temp_Header['DNS'], Dict_Temp_Information_Disclosure['DNS'] = "",""
#                            if (type(Host_Name) == tuple or type(Host_Name) == list):
#                                print ("test")
#                                for i in test:
#                                    if (i != []):
#                                        if (type(i) != list): print (i)
#                                        else: print (i[0])
#                            elif (type(Host_Name) == str): print ("Test2")
                        # Header_Check
                        for Header in r.headers.items():
                            if (Header[0] in Array_Header): Dict_Temp_Header[Header[0]] = Header[1]
                            elif (Header[0] in Array_Information_Disclosure_Header): Dict_Temp_Information_Disclosure[Header[0]] = Header[1]
                            else:
                                for Temp_Header in array(Array_Header):
                                    if (Temp_Header not in Dict_Temp_Header): Dict_Temp_Header[Temp_Header] = "FEHLT"
                            Dict_Result['Header'][url] = Dict_Temp_Header
                            if (len(Dict_Temp_Information_Disclosure) > 0): Dict_Result['Information'][url] = Dict_Temp_Information_Disclosure
                        if (Host_Name != ""): Log_File(f'{strftime("%Y-%m-%d_%H:%M:%S")} - {url} - {Host_Name[0]} - {r}\n{r.headers.items()}\n{Dict_Temp_Header}\n')
                        else: Log_File(f'{strftime("%Y-%m-%d_%H:%M:%S")} - {url} - {r}\n{r.headers.items()}\n{Dict_Temp_Header}\n')
                    except ReadTimeout: Write_Log(url, Host_Name)
                if (scan_ssl != False and '//' in url and 'http' in url): Dict_Result['SSL'] = SSL_Vulns(url, t_seconds)
                if (scan_security_flag != False and '//' in url and 'http' in url): Dict_Result['Security_Flag'] = Check_Security_Flags(url, t_seconds)
                if (scan_fuzzing != False and '//' in url and 'http' in url): Dict_Result['Fuzzing'] = Check_Site_Paths(url, t_seconds)
                if (scan_fuzzing_recurse != False and '//' in url and 'http' in url): pass
                if (scan_ssh != False and '//' not in url):
                    try:
                        if (':' not in url): Dict_Result['SSH'][url] = SSH_Vulns((url, 22))
                        else:
                            Target = url.split(':')
                            Dict_Result['SSH'][url] = SSH_Vulns((Target[0]), int(Target[1]))
                    except paramiko.ssh_exception.SSHException: Write_Log(url, Host_Name)
            except (ConnectionError, gaierror, WebDriverException, RequestException): Write_Log(url, Host_Name)
            finally:
                queue.put(Dict_Result)
                break
    else:
        Write_Log(url, Host_Name)
