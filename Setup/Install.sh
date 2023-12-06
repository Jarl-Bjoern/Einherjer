#!/bin/bash
# Rainer Christian Bjoern Herold

# Variables
TEMP_PATH=$(readlink -f -- "$0")
SCRIPT_NAME=$(basename "${BASH_SOURCE[0]}")
SCRIPT_PATH=${TEMP_PATH::-${#SCRIPT_NAME}-6}

python3 -m virtualenv "$SCRIPT_PATH/venv"
source "$SCRIPT_PATH/venv/bin/activate"
pip3 install -r "$SCRIPT_PATH/Setup/requirements.txt"
deactivate

for LINE in $(cat "$SCRIPT_PATH/Setup/requirements.txt");
do
  pip3 install $LINE || return 0
done
