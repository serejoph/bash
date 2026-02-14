#!/bin/bash
xhost +SI:localuser:root
dpkg --add-architecture i386
apt update
apt install -y \
libnss3-tools \
xterm \
libpam0g \
libpam0g:i386 \
libstdc++5:i386 \
openjdk-8-jre-headless \
./libstdc++5_3.3.6-30ubuntu2_i386.deb
bash ./snx_install_linux30.sh
bash ./instalador.sh