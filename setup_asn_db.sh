#!/bin/bash

pip3 install pyasn
pyasn_util_download.py --latest --filename ./data/pyasnrib.bz2
pyasn_util_convert.py --single ./data/pyasnrib.bz2 ./data/asndb.dat
pyasn_util_asnames.py -o ./data/asnames.json