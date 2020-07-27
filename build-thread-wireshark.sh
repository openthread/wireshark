#!/bin/bash

set -e

rm -rf build || true
mkdir build
(
    cd build
    cmake -GNinja -DDISABLE_WERROR=on \
        -DBUILD_wireshark=OFF \
        -DBUILD_editcap=OFF \
        -DBUILD_capinfos=OFF \
        -DBUILD_captype=OFF \
        -DBUILD_reordercap=OFF \
        -DBUILD_text2pcap=OFF \
        -DBUILD_dftest=OFF \
        -DBUILD_randpkt=OFF \
        -DBUILD_rawshark=OFF \
        -DDUMPCAP_INSTALL_OPTION=suid \
        ..

    ninja
    mv run thread-wireshark
    rm -rf thread-wireshark.tar.gz || true

    tar czf thread-wireshark.tar.gz thread-wireshark/
)

mv build/thread-wireshark.tar.gz ./

echo "Built thread-wireshark successfully:"
ls -l thread-wireshark.tar.gz
