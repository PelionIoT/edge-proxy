#!/bin/bash
#
# Copyright (c) 2023 Izuma Networks
#
# Script to run golint on all folders, where it can find .go -files.
# Use --all option to run golint on all folders, irrespective of findings.
#
# By default golint will not raise an error code, even if it has found something.
# Therefore we mimick that kind of behaviour. Error code will be raised if --all
# is used and even one folder has something.
#
NORM="\u001b[0m"
BOLD="\u001b[1m"
BLUE="\u001b[34m"
RED="\u001b[31m"

whereis_golint=$(whereis golint)
if [ "$whereis_golint" = "golint:" ]
then
    echo "golint command not found, please install it with sudo apt install golint (or similar)."
    exit 2
fi

quick_fail=0
if [ $# -eq 0 ]
then
    set -e
    quick_fail=1
else
    if [ $# -eq 1 ] && [ "$1" = "--all" ]
    then
        echo "--all option invoked, will not stop for errors."
    else
        set -e
        quick_fail=1
    fi
fi

# Get all go files, sort them, extract the folder names and get the unique ones out of those
godirs=$(find . -iname '*.go' |sort | awk 'BEGIN { FS = "/" } ; {print $2}' | uniq)
# godirs_array=( $godirs ) -- works, but shellcheck complaints
# warning: Quote to prevent word splitting/globbing, or split robustly with mapfile or read -a. [SC2206]
mapfile -t godirs_array <<< "$godirs"
curdir=$(pwd)
retcode=0
total_hits=0
for godir in "${godirs_array[@]}"
do
    echo -e "${BLUE}Running golint on $godir${NORM}"
    cd "$godir" || exit 1
    golint
    # Number of hits from golint
    hits=$(golint | wc -l)
    total_hits=$((total_hits + hits))
    if [ "$hits" != "0" ]
    then
        retcode=2
        if [ $quick_fail != "0" ]
        then
            echo -e "${BOLD}${RED}Stopped, there are findings.${NORM}"
            exit $retcode
        fi
    fi
    cd .. || exit 1
done
cd "$curdir"
if [ $retcode != "0" ]
then
    echo -e "${BOLD}${RED}Done, there are $total_hits findings.${NORM}"
else
    echo -e "${BOLD}${BLUE}Done, clean run.${NORM}"
fi
exit $retcode
