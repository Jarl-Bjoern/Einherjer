#!/bin/bash
# Rainer Christian Bjoern Herold

# Variables
TEMP_PATH=$(readlink -f -- "$0")
SCRIPT_NAME=$(basename "${BASH_SOURCE[0]}")
SCRIPT_PATH=${TEMP_PATH::-${#SCRIPT_NAME}-13}
BASE_PATH=${TEMP_PATH::-${#SCRIPT_NAME}-23}

python3 -m virtualenv $BASE_PATH/venv
source $BASE_PATH/venv/bin/activate
pip3 install -r Setup/requirements.txt
deactivate

pip3 install -r Setup/requirements.txt
