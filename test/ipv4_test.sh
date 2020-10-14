#! /bin/bash

source venv/bin/activate

# Test des hôtes mis en place dans le docker-compose.yml

python3 port_scanner.py -s -t 172.20.128.2 172.20.128.3
python3 port_scanner.py -s -t 172.20.128.2/24
python3 port_scanner.py -t 172.20.128.2