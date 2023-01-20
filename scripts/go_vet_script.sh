#!/bin/bash
#
# Copyright (c) 2023 Izuma Networks
#
# Script to run go vet on all folders, where it can find .go -files.
# Use --all option to run go vet on all folders, irrespective of findings.
#
NORM="\u001b[0m"
BOLD="\u001b[1m"
BLUE="\u001b[34m"
RED="\u001b[31m"
DGREY="\u001b[90m"

if [ $# -eq 0 ]
then
    set -e
else
    if [ $# -eq 1 ] && [ "$1" = "--all" ]
    then
        echo "--all option invoked, will not stop for errors."
    else
        set -e
    fi
fi

# Get all go files, sort them, extract the folder names and get the unique ones out of those
godirs=$(find . -iname '*.go' -exec dirname {} \; | sort | uniq)
# godirs_array=( $godirs ) -- works, but shellcheck complaints
# warning: Quote to prevent word splitting/globbing, or split robustly with mapfile or read -a. [SC2206]
mapfile -t godirs_array <<< "$godirs"
curdir=$(pwd)
hits=0
total=0
for godir in "${godirs_array[@]}"
do
    if [ "$godir" != "vendor" ]
    then
        echo -e "${BOLD}${BLUE}Running go vet on $godir${NORM}"
        cd "$godir" || exit 1
        tmpfile=$(mktemp)
        go vet
        # This gets hacky because go vet prints all it's stuff out to stderr.
        # So, simple go vet | wc -l will not work! Working around with tempfile.
        go vet >"$tmpfile" 2>&1
        hits=$(wc -l "$tmpfile" | awk NF=1)
        rm "$tmpfile"
        total=$((total+hits))
        cd "$curdir" || exit 1
    else
        echo -e "${BOLD}${DGREY}Skipping go vet on $godir${NORM}"
    fi
done
cd "$curdir"
if [ $total -ne 0 ]
then
    echo -e "${BOLD}${RED}Done, $total findings.${NORM}"
else
    echo -e "${BOLD}Done, clean go vet run.${NORM}"
fi