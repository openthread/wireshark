from ubuntu:18.04

RUN apt-get update
RUN apt-get install -y git libpcap-dev libwireshark-dev ninja-build libgcrypt20-dev libglib2.0-dev bison flex cmake

RUN git clone https://github.com/openthread/wireshark.git --branch thread-wireshark/ot-pktverify --depth 1
RUN cd wireshark && ./build-thread-wireshark.sh

