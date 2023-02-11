#!/bin/bash
source venv/bin/activate
sudo python3 Einherjer.py "$@"
deactivate
