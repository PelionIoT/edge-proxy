#!/bin/bash
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
godirs=$(find . -iname '*.go' |sort | awk 'BEGIN { FS = "/" } ; {print $2}' | uniq)
# godirs_array=( $godirs ) -- works, but shellcheck complaints
# warning: Quote to prevent word splitting/globbing, or split robustly with mapfile or read -a. [SC2206]
mapfile -t godirs_array <<< "$godirs"
curdir=$(pwd)
for godir in "${godirs_array[@]}"
do
    echo "Running go vet on $godir"
    cd "$godir" || exit 1
    go vet
    cd .. || exit 1
done
cd "$curdir"
echo "Done."
