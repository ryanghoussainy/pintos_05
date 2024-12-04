#!/bin/bash

make clean

make check | while IFS=
read -r line; do
    if echo "$line" | grep -q "pass"; then
        echo -e "\033[32m$line\033[0m"
    elif echo "$line" | grep -q "FAIL"; then
        echo -e "\033[31m$line\033[0m"
    else
        echo "$line"
    fi
done