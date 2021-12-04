#!/bin/bash

# activate venv if exists
if [[ -d 'env' ]]; then
    source env/bin/activate
else
    python3 -m venv env
    source env/bin/activate
fi

python3 -m pip install -r requirements.txt