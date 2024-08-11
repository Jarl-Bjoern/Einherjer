#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def Screenshot_Table_File(location, Body_HTML = ""):
    Head_HTML = """<!DOCTYPE html>
<html>
<head>
<style>
table, th, td {
  border: 1px solid turquoise;
  border-collapse: collapse;
}
.center {
  display: block;
  margin-left: auto;
  margin-right: auto;
}
h1 {
  color: Orange;
}
</style>

<title>
    Einherjer - Results
</title>
<body style="background-color:black">
<table style="width:100%">
<h1>Einherjer Version 0.8</h1>
<hr><br />
<tr>
"""
    Head_HTML += "<th><font color='Orange'>Host</font></th>"
    Head_HTML += "<th><font color='Orange'>Screenshot</font></th>\n</tr>"
    for Body in listdir(location):
        Body_HTML += "<tr>"
        Body_HTML += f"<td><center><font color='Orange'>{Body.split('(')[1].split(')')[0].replace('_', ':')}</font></center></td>\n"
        Body_HTML += f"<td><img class='center' src='{join(location, Body)}' width=800/></td>\n"
        Body_HTML += "</tr>\n"
    Footer_HTML = """</table>
<br /><br />
<center><font color='Red'>1</font></center>
<br />
</body>
</html>"""

    with open(join(location.replace('/Screenshots', '/'), f'screenshots.html'), 'w') as f:
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
