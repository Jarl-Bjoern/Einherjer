#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def Screenshot_Table_File(location, Body_HTML = ""):
    Head_HTML = f"""<!DOCTYPE html>
<html>
<head>
<title>
    Scan - Result
</title>
<body style="background-color:black;font-color:white">
<h1>Einherjer - Screenshots</h1>
<table style="width:100%">
<tr>
"""
    Head_HTML += "<th>URL</th>"
    Head_HTML += "<th>DNS</th>"
    for Head in listdir(location):
        Head_HTML += f"<th><img src='{join(location, Head)}'/></th>"
    Head_HTML += "</tr>"
    Footer_HTML = """</table>
</body>
</html>"""

    with open(join(location, f'screenshots.html'), 'w') as f:
        f.write(Head_HTML), f.write(Body_HTML), f.write(Footer_HTML)


def HTML_Table(Dict_Result, location, Body_HTML = ""):
    Head_HTML = f"""<!DOCTYPE html>
<html>
<head>
<title>
    Scan - Result
</title>
<body>
<h1>HTTP_Header</h1>
<table style="width:100%">
<tr>
"""
    Head_HTML += "<th>URL</th>"
    Head_HTML += "<th>DNS</th>"
    for Head in list(Dict_Header):
        Head_HTML += f"<th>{Head}</th>"
    Head_HTML += "</tr>"
    Footer_HTML = """</table>
</body>
</html>"""

    for Target in Dict_Result['Header']:
        Body_HTML += rf"""<tr>
    <td>{Target}</td>"""
        for Result_Left, Result_Right in Dict_Result['Header'].items():
            if (Result_Left == "DNS" and Result_Right == ""):        Result_Right = "FEHLT"

            if (Result_Left != "DNS" and Result_Right != "FEHLT"):   Body_HTML += r'  <td><p style="text-align:center;">✓</p></td>'
            elif (Result_Left == "DNS" and Result_Right != "FEHLT"): Body_HTML += rf'  <td><p style="text-align:center;">{Result_Right}</p></td>'
            elif (Result_Left == "DNS" and Result_Right == "FEHLT"): Body_HTML += r'  <td><p style="text-align:center;">-</p></td>'
            else:                                                    Body_HTML += r'  <td><p style="text-align:center;">X</p></td>'

    while True:
        try:
            with open(join(location, f'results.html'), 'w') as f:
                f.write(Head_HTML), f.write(Body_HTML), f.write(Footer_HTML)
            break
        except PermissionError: Logs.Error_Message(f"The file is already open!\nPlease close it and wait five seconds.")
        sleep(5)
