#!/bin/sh
# start lightnion for integration tests

source venv/bin/activate
cd ../../../../
export PYTHONPATH="$PWD"
python -m lightnion.proxy -s 127.0.0.1:5001 -d 7001 -c 8001 -vvv
