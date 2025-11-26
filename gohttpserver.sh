#!/bin/bash

nohup ./dist/gohttpserver-linux-amd64-1.1.2 --title "XX File Server" --prefix /foo --addr :8000 --xheaders --auth-type http --upload --delete > gohttpserver-linux-amd64.log &
