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

def Create_JSON(Dict_Result):
    try: import json
    except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")
