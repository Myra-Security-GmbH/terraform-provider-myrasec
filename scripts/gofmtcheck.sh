#!/usr/bin/env bash

files=$(gofmt -l `find . -name '*.go' | grep -v vendor`)
if [ -n "${files}" ]; then
    echo "${files}"
    echo "You should run \`make fmt\` to format the files"
fi

exit 0