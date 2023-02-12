#!/bin/bash
# Rainer Christian Bjoern Herold
TEMP_PATH=$(readlink -f -- "$0")
SCRIPT_NAME=$(basename "${BASH_SOURCE[0]}")
SCRIPT_PATH=${TEMP_PATH::-${#SCRIPT_NAME}-13}
BASE_PATH=${TEMP_PATH::-${#SCRIPT_NAME}-23}
if [[ -d "$BASE_PATH/venv" ]]; then
        source "$BASE_PATH/"venv/bin/activate
        sudo python3 "$SCRIPT_PATH/main.py" "$@"
        deactivate
else
        echo "Please use a virtual environment!\n\nvirtualenv $BASE_PATH/venv\nsource $BASE_PATHvenv/bin/activate\npip3 install -r Setup/requirements.txt\ndeactivate"
fi
