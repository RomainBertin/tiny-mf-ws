#!/bin/sh

pids=$(ps -A | grep tinymfws | awk '{print $1}')
if [ ! -z "$pids" ]; then
    kill -9 $pids
fi

