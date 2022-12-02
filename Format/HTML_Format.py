#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer C. B. Herold

# Libraries
try:
    from resources.VF import *
except ImportError:
    from sys import path as syspath
    syspath.append('.')
    from resources.VF import *

def HTML_Table(Dict_Result, Body_HTML = ""):
    global Location
    Head_HTML = f"""<!DOCTYPE html>
<html>
<head>
<title>
    Scan - Result
</title>
<body>
<h1>{File_Name}</h1>
<table style="width:100%">
<tr>
"""
    Head_HTML += "<th>URL</th>"
    Head_HTML += "<th>DNS</th>"
    for Head in Array_Header:
        Head_HTML += f"<th>{Head}</th>"
    Head_HTML += "</tr>"
    Footer_HTML = """</table>
</body>
</html>"""

    for Target in Dict_Result:
        Body_HTML += rf"""<tr>
    <td>{Target}</td>"""
        for Result_Left, Result_Right in Dict_Result['Header'][Target].items():
            if ((Result_Left == "X-XSS-Protection" or Result_Left == Array_Header[1].lower() or Result_Left == Array_Header[1].isupper()) and (Result_Right == "1" or (Result_Right == "1; mode=block" or Result_Right == "1; mode=BLOCK"))): Result_Right = "FEHLT"
            elif ((Result_Left == "X-Content-Type-Options" or Result_Left == Array_Header[4].lower() or Result_Left == Array_Header[4].isupper()) and (Result_Right != "nosniff" or Result_Right != "NOSNIFF")): Result_Right = "FEHLT"
            elif ((Result_Left == "X-Frame-Options" or Result_Left == Array_Header[0].lower() or Result_Left == Array_Header[0].isupper()) and (Result_Right != "DENY" or Result_Right != "deny")): Result_Right = "FEHLT"

            if (Result_Right != "FEHLT"): Body_HTML += r'  <td><p style="text-align:center;">✓</p></td>'
            else: Body_HTML += r'  <td><p style="text-align:center;">X</td>'

            if (Result_Left == 'Referrer-Policy'): Body_HTML += r"</tr><br />"

    while True:
        try:
            with open(join(Location, f'{Date}-main.html'), 'w') as f:
                f.write(Head_HTML), f.write(Body_HTML), f.write(Footer_HTML)
            break
        except PermissionError: Error_Message(f"The file {File_Name} is already open!\nPlease close it and wait five seconds.")
        sleep(5)
