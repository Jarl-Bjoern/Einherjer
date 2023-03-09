#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def Latex_Table(Dict_Result, location, Table_Body = ""):
    Define_Color = r"""\input{libs/packages.tex}
\definecolor{redbg}{rgb}{0.85,0.1,0.1}
\definecolor{greenbg}{rgb}{0.1,0.85,0.1}"""
    with open(join(location, f'main.tex'), 'a') as f:
        f.write(Define_Color)

    Standard_Head = r"""\begin{longtable}
	[]{@{}lccccccc@{}}
	\toprule
	\begin{minipage}[t][3.5cm][b]{0.5\textwidth}URL
	\end{minipage}
			                                            & \rotatebox{270}{X-Frame-Options} & \rotatebox{270}{X-XSS-Protection} & \rotatebox{270}{Content-Security-Policy} & \rotatebox{270}{Strict-Transport-Security} & \rotatebox{270}{X-Content-Type-Options} & \rotatebox{270}{Referrer-Policy}\tabularnewline
	\midrule
	\endhead
"""
    Table_Footer = r"""     \bottomrule
\end{longtable}"""
    for Target in Dict_Result['Header']:
        Table_Body += rf"	\url{Target}"
        for Result_Left, Result_Right in Dict_Result['Header'][Target].items():
            if ((Result_Left == "X-XSS-Protection" or Result_Left == Array_Header[1].lower() or Result_Left == Array_Header[1].isupper()) and (Result_Right == "1" or (Result_Right == "1; mode=block" or Result_Right == "1; mode=BLOCK"))): Result_Right = "FEHLT"
            elif ((Result_Left == "X-Content-Type-Options" or Result_Left == Array_Header[4].lower() or Result_Left == Array_Header[4].isupper()) and (Result_Right != "nosniff" or Result_Right != "NOSNIFF")): Result_Right = "FEHLT"
            elif ((Result_Left == "X-Frame-Options" or Result_Left == Array_Header[0].lower() or Result_Left == Array_Header[0].isupper()) and (Result_Right != "DENY" or Result_Right != "deny")): Result_Right = "FEHLT"

            if (Result_Right != "FEHLT"): Table_Body += r"& \textcolor{greenbg}\CheckmarkBold"
            else: Table_Body += r"& \textcolor{redbg}\XSolid"

            if (Result_Left == 'Referrer-Policy'): Table_Body += r"""\tabularnewline
"""

    while True:
        try:
            with open(join(location, f'Findings.tex'), 'a') as f:
                f.write(Standard_Head), f.write(Table_Body), f.write(Table_Footer)
            break
        except PermissionError: Error_Message(f"The file 'Findings.tex' is already open!\nPlease close it and wait five seconds.")
        sleep(5)
