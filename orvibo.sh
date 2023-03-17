#!/bin/sh
mkdir -p /tmp/log
PTH=$( cd "$( dirname "${BASH_SOURCE:-$0}" )" && pwd )
source $PTH/venv/bin/activate
cd $PTH
FILEOUT=/tmp/log/`date "+%Y%m%d"`_orvpy.out
FILEERR=/tmp/log/`date "+%Y%m%d"`_orvpy.err
FILEDEV=/tmp/log/`date "+%Y%m%d"`_orvpy_dev.xml
cp -f "$PTH/devices.xml" "$FILEDEV"
export MAINPTH=$PTH
( sleep 60 && python3 src/main.py -c "$FILEDEV" -s 10001 -g 10002 -p 10000 -b 192.168.25.255 --active_on_finish --mqtt-host=127.0.0.1 -t 3 --mqtt-port=8913 --prime-host=192.168.25.51 --prime-port=80 --prime-port2=6004 --prime-code=4133 --prime-pass=pass --pid=/tmp/orvpy_pid.pid --home-assistant=homeassistant ) >"$FILEOUT" 2>"$FILEERR" &
#/usr/bin/python main.py -c $PTH/devices.xml -s 10001 -b 192.168.25.255 --active_on_finish --mqtt-host=rbx1-fr.quadhost.net --mqtt-port=8913 >$FILEOUT 2>$FILEERR &
#/usr/bin/python main.py -c $PTH/devices.xml -s 10001 -b 192.168.25.255 --active_on_finish >$FILEOUT 2>$FILEERR &
