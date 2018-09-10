#!/bin/bash

openssl req -new -x509 -days 365 -nodes -out cert.pem -keyout key.pem
