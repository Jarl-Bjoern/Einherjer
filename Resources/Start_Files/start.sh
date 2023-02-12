#!/bin/bash
# Rainer Christian Bjoern Herold

# Variables
TEMP_PATH=$(readlink -f -- "$0")
SCRIPT_NAME=$(basename "${BASH_SOURCE[0]}")
SCRIPT_PATH=${TEMP_PATH::-${#SCRIPT_NAME}-13}
BASE_PATH=${TEMP_PATH::-${#SCRIPT_NAME}-23}

# Color
BLUE='\033[0;34m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
ORANGE='\033[1;33m'
NORANGE='\033[0;33m'
PURPLE='\033[0;35m'
UNDERLINE='\033[0;4m'
NOCOLOR='\033[0m'

# Main
if [[ -d "$BASE_PATH/venv" ]]; then
        source "$BASE_PATH/"venv/bin/activate
        sudo python3 "$SCRIPT_PATH/main.py" "$@"
        deactivate
else
        echo -e "\n${RED}Please use a virtual python environment!${NOCOLOR}\n\nInstruction:\n${CYAN}-------------------------------------\n${ORANGE}virtualenv $BASE_PATH/venv\nsource $BASE_PATH/venv/bin/activate\npip3 install -r Setup/requirements.txt\ndeactivate${NOCOLOR}"
fi
