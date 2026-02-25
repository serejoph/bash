#!/bin/bash

while getopts "p:" opt; do
  case $opt in
    p)
      profile_path="$OPTARG"
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      ;;
  esac
done
export profile_path

xhost +SI:localuser:root
dpkg --add-architecture i386
apt update
apt install -y \
libnss3-tools \
xterm \
libpam0g \
libpam0g:i386 \
libstdc++5:i386 \
libstdc++6:i386 \
openjdk-8-jre-headless \
./libstdc++5_3.3.6-30ubuntu2_i386.deb
bash ./snx_install_linux30.sh
bash ./vpn.sh
