#! /bin/bash

# création d'une virtualenv
pip3 install --upgrade virtualenv
virtualenv -p python3 venv
source venv/bin/activate
pip3 install -r requirements.txt