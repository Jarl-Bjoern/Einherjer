#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def Create_PDF():
    try:
        if (osname == 'nt'): from docx2pdf import convert
        else: import aspose.words as aw
    except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")

    while True:
        try:
            if (osname == 'nt'): convert(join(Location, f'{File_Name}.docx'), join(Location, f'{File_Name}.pdf'))
            else:
                doc = aw.Document(join(Location, f'{File_Name}.docx'))
                doc.save(join(Location, f'{File_Name}.pdf'))
            break
        except FileNotFoundError:
            break
        except PermissionError: Error_Message(f"The file {File_Name}.pdf is already open!\nPlease close it and wait five seconds.")
        sleep(5)
