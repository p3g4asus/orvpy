#!/bin/bash

mkdir -p /tmp/log
PTH=$( cd "$( dirname "${BASH_SOURCE:-$0}" )" && pwd )
source $PTH/venv/bin/activate
cd $PTH
set -a
. myscript.conf
set +a
FILEOUT=/tmp/log/`date "+%Y%m%d"`_orvpy.out
FILEDEV=/tmp/log/`date "+%Y%m%d"`_orvpy_dev.xml
cp -f "$PTH/devices.xml" "$FILEDEV"
export MAINPTH=$PTH
arg="src/main.py -c $FILEDEV -s 10001 -g 10002 -p 10000 -b 192.168.25.255 --active_on_finish --mqtt-host="${mqtt_host}" -t 3 --mqtt-port=8913 --prime-host="${prime_host}" --prime-port=80 --prime-port2=6004 --prime-code="${prime_user}" --prime-pass="${prime_pass}" --pid=/tmp/orvpy_pid.pid --home-assistant=homeassistant"
echo $arg
if [ "${async}" = true ]; then
    echo "Spawn!"
    (  python3 $(echo -n $arg) ) > $FILEOUT 2>&1 &
else
    (  python3 $(echo -n $arg) ) > $FILEOUT 2>&1
fi