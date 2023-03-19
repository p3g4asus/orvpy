#!/bin/bash
config() {
    val=$((grep -E "^$1=" myscript.conf 2>/dev/null || echo "$1=__DEFAULT__") | head -n 1 | cut -d '=' -f 2-)
    echo -n $val
}

prime_h=$(config prime_host)
prime_u=$(config prime_user)
prime_p=$(config prime_pass)
mqtt_h=$(config mqtt_host)
async=$(config async)
mkdir -p /tmp/log
PTH=$( cd "$( dirname "${BASH_SOURCE:-$0}" )" && pwd )
source $PTH/venv/bin/activate
cd $PTH
FILEOUT=/tmp/log/`date "+%Y%m%d"`_orvpy.out
FILEDEV=/tmp/log/`date "+%Y%m%d"`_orvpy_dev.xml
cp -f "$PTH/devices.xml" "$FILEDEV"
export MAINPTH=$PTH
arg="src/main.py -c $FILEDEV -s 10001 -g 10002 -p 10000 -b 192.168.25.255 --active_on_finish --mqtt-host=$mqtt_h -t 3 --mqtt-port=8913 --prime-host=$prime_h --prime-port=80 --prime-port2=6004 --prime-code=$prime_u --prime-pass=$prime_p --pid=/tmp/orvpy_pid.pid --home-assistant=homeassistant"
echo $arg
if [ "$async" = true ]; then
    (  python3 $(echo -n $arg) ) > $FILEOUT 2>&1 &
else;
    (  python3 $(echo -n $arg) ) > $FILEOUT 2>&1
fi
#/usr/bin/python main.py -c $PTH/devices.xml -s 10001 -b 192.168.25.255 --active_on_finish --mqtt-host=rbx1-fr.quadhost.net --mqtt-port=8913 >$FILEOUT 2>$FILEERR &
#/usr/bin/python main.py -c $PTH/devices.xml -s 10001 -b 192.168.25.255 --active_on_finish >$FILEOUT 2>$FILEERR &
