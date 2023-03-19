#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def Create_PDF():
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
