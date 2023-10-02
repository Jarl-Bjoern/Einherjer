#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from .Libraries import *
from ..Standard_Operations.Colors import Colors
from ..Standard_Operations.Standard import *
from ..Standard_Operations.Logs import *

def QRCode_Analysis(picture_target_location, Array_Filter = ['.png','.bmp','.jpg','.jpeg','.gif']):
        for Images in listdir(picture_target_location):
                if any(File_Format in Images for File_Format in Array_Filter):
                        img = Image.open(join(args.Target_Pictures, Images))
                        output = str(pyzbar.decode(img)).split("'")[1]
                        print (Colors.ORANGE+f'Token:\n'+Colors.RESET+'{output}\n'+Colors.CYAN'------------------------------------------------------\n\n'+Colors.RESET)
