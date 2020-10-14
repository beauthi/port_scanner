#! /bin/bash

source venv/bin/activate

# Test des hôtes mis en place dans le docker-compose.yml

python3 port_scanner.py -s -t 2001:3200:3200::3
python3 port_scanner.py -s -t 2001:3200:3200::2
python3 port_scanner.py -f test/ipv6.in