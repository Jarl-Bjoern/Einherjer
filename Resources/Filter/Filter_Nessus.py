#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def Nessus_Reader(nessus_file_location, output_location, Array_Temp = []):
  # <preference><name>TARGET</name><value> --> Host | <plugin_output> Installed version | plugin_name (see_also)
  if (isfile(nessus_file_location) and nessus_file_location.endswith('.nessus')):
      with open(nessus_file_location, 'r') as f:
          Report = f.read().splitlines()

  for Result in Report:
      pass

  return Array_Temp
