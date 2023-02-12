#!/bin/bash
# Rainer Christian Bjoern Herold
source venv/bin/activate
echo "$@"
sudo python3 ../main.py "$@"
deactivate
