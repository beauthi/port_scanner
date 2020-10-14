"""
Récupération des onfigurations au niveau utilisateur.

:file config.py
:author Thibaut PASSILLY
:date 09.10.2020
"""

import json
import os


def get_config():
    current_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)))
    root_folder = os.path.abspath(os.path.join(current_folder, os.pardir))
    json_input = "config.json"
    with open("{}/{}".format(root_folder, json_input), "r") as json_content:
        json_object = json.load(json_content)
    return json_object


config_dict = get_config()
