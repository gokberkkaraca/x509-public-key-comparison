#!/bin/sh

if [ "$#" -ne 1 ]; then
    echo "Illegal number of parameters: Please provide path to certificates folder"
    exit
fi

go build
./x509-public-key-comparison $1 > public_key_comparison_results.json
python3 analyze.py