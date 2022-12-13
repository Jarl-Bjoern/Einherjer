[![Linux](https://svgshare.com/i/Zhy.svg)](https://svgshare.com/i/Zhy.svg)
[![Python 3.10](https://img.shields.io/badge/python-3.10-blue.svg)](https://www.python.org/downloads/release/python-3100/)
![visitors](https://visitor-badge.glitch.me/badge?page_id=jarl-bjoern/einherjer&left_color=grey&right_color=blue)
<a href="https://github.com/jarl-bjoern">
      <img title="Follower" src="https://img.shields.io/github/followers/Jarl-Bjoern.svg?style=social&label=Follow&maxAge=2592000"><a href="https://github.com/Jarl-Bjoern?tab=followers"></a>

# General Description
UNDER CONSTRUCTION

Not all functions are done

# Table of Contents
- [How to download and install the tool](#download_install)
  - [Download and start the tool](#start_install)
  - [Using the help section to see which parameters do we have](#help_install)

<a name="start_install"></a>
## Download and start the tool
```bash
sudo git clone https://github.com/Jarl-Bjoern/einherjer/
cd einherjer
sudo python3 Einherjer.py
```

<a name="help_install"></a>
## Using the help section to see which parameters do we have
```bash
usage: Einherjer.py -f {csv,docx,html,json,latex,pdf,tex,xlsx,xml} -s SLEEP [-sA [SCAN_ALL]] [-sSs [SCAN_SITE_SCREENSHOT]] [-sSsr [SCAN_SITE_SCREENSHOT_RECURSIVE]] [-sSSL [SCAN_SITE_SSL]] [-sSh [SCAN_SITE_HEADER]] [-sSF [SCAN_SITE_FUZZING]] [-sSSH [SCAN_SSH]] [-sSSF [SCAN_SECURITY_FLAGS]] [-sC [SCAN_CREDENTIALS]]
                    [-aNr ADD_NMAP_SSH_RESULT] [-aW ADD_WORDLIST] [-amW ADD_MULTIPLE_WORDLISTS] [-iL IMPORT_LIST] [-t TARGET] [-aP ADD_PROXY] [-o OUTPUT_LOCATION] [-rCssh READ_CONFIG_SSH_CIPHERS] [-rCssl READ_CONFIG_SSL_CIPHERS] [-mx MAX_CONNECTIONS]
                    [-m {Multiprocessing,multiprocessing,mp,MP,threading,Threading,t,Thread,thread}] [-to TIMEOUT] [-r [RANDOM_ORDER]] [-tHo THREAD_TIMEOUT] [-app APPEND_TO_EXISTING_XLSX] [-c CUSTOM_CHROMIUM_PATH] [-h]

-------------------------------------------------------------------------------------
|  Created by Rainer C. B. Herold                                                   |                                                                                                                                                                                                                                       
|  Copyright 2022. All rights reserved.                                             |                                                                                                                                                                                                                                       
|                                                                                   |                                                                                                                                                                                                                                       
|  Please do not use the program for illegal activities.                            |                                                                                                                                                                                                                                       
|                                                                                   |                                                                                                                                                                                                                                       
|  If you got any problems don't hesitate to contact me so I can try to fix them.   |                                                                                                                                                                                                                                       
|                                                                                   |                                                                                                                                                                                                                                       
|  If you use the "Kali-Last-Snapshot" repository, you might install a slightly     |                                                                                                                                                                                                                                       
|  older driver of Chromium with the command "apt install -y chromium". If this     |                                                                                                                                                                                                                                       
|  is the case, then you should check after the installation with the command       |                                                                                                                                                                                                                                       
|  "apt-cache policy chromium" which version was installed and then download the    |                                                                                                                                                                                                                                       
|  appropriate Chrome Webdriver from the following page                             |                                                                                                                                                                                                                                       
|  "https://chromedriver.chromium.org/downloads" and replace it instead.            |                                                                                                                                                                                                                                       
-------------------------------------------------------------------------------------                                                                                                                                                                                                                                       
                                                                                                                                                                                                                                                                                                                            

required arguments:
  -f {csv,docx,html,json,latex,pdf,tex,xlsx,xml}, --format {csv,docx,html,json,latex,pdf,tex,xlsx,xml}
                        Specify your used format like xlsx (Excel), Docx (MS Word), LaTeX or PDF.
                                                                                                                                                                                                                                                                                                                            
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               
  -s SLEEP, --sleep SLEEP
                        Set the pauses between the scans to do not DDoS the target.
                                                                                                                                                                                                                                                                                                                            
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               

scan arguments:
  -sA [SCAN_ALL], --scan-all [SCAN_ALL]
                        With this it is possible to scan all functions
                                                                                                                                                                                                                                                                                                                            
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               
  -sSs [SCAN_SITE_SCREENSHOT], --scan-site-screenshot [SCAN_SITE_SCREENSHOT]
                        With this function you can create screenshots of the start pages.
                                                                                                                                                                                                                                                                                                                            
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               
  -sSsr [SCAN_SITE_SCREENSHOT_RECURSIVE], --scan-site-screenshot-recursive [SCAN_SITE_SCREENSHOT_RECURSIVE]
                        With this function you can create screenshots of the target pages, but with the 
                        special feature that any results are checked with the fuzzing and screenshots are
                        created from them in each case.
                                                                                                                                                                                                                                                                                                                            
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               
  -sSSL [SCAN_SITE_SSL], --scan-site-ssl [SCAN_SITE_SSL]
                        With this function you check the TLS/SSL connections for vulnerabilities.
                                                                                                                                                                                                                                                                                                                            
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               
  -sSh [SCAN_SITE_HEADER], --scan-site-header [SCAN_SITE_HEADER]
                        Use this function to check the HTTP headers for useful information and misconfigurations.
                                                                                                                                                                                                                                                                                                                            
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               
  -sSF [SCAN_SITE_FUZZING], --scan-site-fuzzing [SCAN_SITE_FUZZING]
                        With this function you check the web services for hidden directories or files.
                                                                                                                                                                                                                                                                                                                            
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               
  -sSSH [SCAN_SSH], --scan-ssh [SCAN_SSH]
                        With this function you check the SSH service for vulnerabilities.
                                                                                                                                                                                                                                                                                                                            
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               
  -sSSF [SCAN_SECURITY_FLAGS], --scan-security-flags [SCAN_SECURITY_FLAGS]
                        With this function you check the cookie flags for vulnerabilities.
                                                                                                                                                                                                                                                                                                                            
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               
  -sC [SCAN_CREDENTIALS], --scan-credentials [SCAN_CREDENTIALS]
                        UNDER CONSTRUCTION
                                                                                                                                                                                                                                                                                                                            
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               
  -aNr ADD_NMAP_SSH_RESULT, --add-nmap-ssh-result ADD_NMAP_SSH_RESULT
                        With this function you analyze the ssh output of nmap.
                                                                                                                                                                                                                                                                                                                            
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               
  -aW ADD_WORDLIST, --add-wordlist ADD_WORDLIST
                        With this function you add a word list for fuzzing.
                                                                                                                                                                                                                                                                                                                            
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               
  -amW ADD_MULTIPLE_WORDLISTS, --add-multiple-wordlists ADD_MULTIPLE_WORDLISTS
                        With this function you add several word lists which are checked for duplicates and 
                        sort them out for fuzzing.
                                                                                                                                                                                                                                                                                                                            
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               

target arguments:
  -iL IMPORT_LIST, --import-list IMPORT_LIST
                        Import your target list in the following example:
                        http://192.168.2.2                                                                                                                                                                                                                                                                                  
                        https://192.168.2.3                                                                                                                                                                                                                                                                                 
                        https://192.168.2.4:8443                                                                                                                                                                                                                                                                            
                        192.168.2.5:22                                                                                                                                                                                                                                                                                      
                                                                                                                                                                                                                                                                                                                            
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               
  -t TARGET, --target TARGET
                        Specify a single target.
                                                                                                                                                                                                                                                                                                                            
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               

config arguments:
  -aP ADD_PROXY, --add-proxy ADD_PROXY
                        Specify your proxy.
                                                                                                                                                                                                                                                                                                                            
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               
  -o OUTPUT_LOCATION, --output-location OUTPUT_LOCATION
                        Specify the location where the result should be saved.
                                                                                                                                                                                                                                                                                                                            
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               
  -rCssh READ_CONFIG_SSH_CIPHERS, --read-config-ssh-ciphers READ_CONFIG_SSH_CIPHERS
                        UNDER CONSTRUCTION
                                                                                                                                                                                                                                                                                                                            
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               
  -rCssl READ_CONFIG_SSL_CIPHERS, --read-config-ssl-ciphers READ_CONFIG_SSL_CIPHERS
                        UNDER CONSTRUCTION
                                                                                                                                                                                                                                                                                                                            
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               

performance arguments:
  -mx MAX_CONNECTIONS, --max-connections MAX_CONNECTIONS
                        Defines the max connections via threads or processes for every try to scan.
                        
                        Default: 8
                                                                                                                             
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               
  -m {Multiprocessing,multiprocessing,mp,MP,threading,Threading,t,Thread,thread}, --method {Multiprocessing,
                        multiprocessing,mp,MP,threading,Threading,t,Thread,thread}
                        Defines which method you wanted to use.
                                                                                                            
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               
  -to TIMEOUT, --timeout TIMEOUT
                        Specify the connection http timeout in seconds. Default: 30 seconds
                                                                                                                                                                                                                                                                                                                            
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               
  -r [RANDOM_ORDER], --random-order [RANDOM_ORDER]
                        UNDER CONSTRUCTION
                                                                                                                                                                                                                                                                                                                            
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               
  -tHo THREAD_TIMEOUT, --thread-timeout THREAD_TIMEOUT
                        UNDER CONSTRUCTION
                                                                                                                                                                                                                                                                                                                            
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               

optional arguments:
  -app APPEND_TO_EXISTING_XLSX, --append-to-existing-xlsx APPEND_TO_EXISTING_XLSX
                        UNDER CONSTRUCTION.
                                                                                                                                                                                                                                                                                                                            
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               
  -c CUSTOM_CHROMIUM_PATH, --custom-chromium-path CUSTOM_CHROMIUM_PATH
                        Specify the location of your custom chromium.
                                                                                                                                                                                                                                                                                                                            
                        -------------------------------------------------------------------------------------                                                                                                                                                                                                               
  -h, --help            Show this help message and exit.
                                                                                                                                                                                                                                                                                                                            
                        ------------------------------------------------------------------------------------- 
```

# Remark
The Script is still under development
