#! /bin/bash

source venv/bin/activate

python3 port_scanner.py -s -t scanme.nmap.org
python3 port_scanner.py -s -t internet.in
python3 port_scanner.py -t scanme.nmap.org