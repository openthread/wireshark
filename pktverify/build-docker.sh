#!/bin/bash

docker build . -t thread-wireshark

docker run -v/tmp:/tmp --rm thread-wireshark cp thread-wireshark.tar.gz /tmp

docker image rm thread-wireshark

ls -l /tmp/thread-wireshark.tar.gz

