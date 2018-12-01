export LD_LIBRARY_PATH=/lib:/usr/lib:/opt/lib:/opt/usr/lib
PTH=/opt/prg/orvpy
cd $PTH
FILEOUT=$PTH/dump/`date "+%Y%m%d"`_epg.out
FILEERR=$PTH/dump/`date "+%Y%m%d"`_epg.err
FILEDEV=$PTH/dump/`date "+%Y%m%d"`_dev.xml
cp -f "$PTH/devices.xml" "$FILEDEV"
/usr/bin/python main.py -c "$FILEDEV" -s 10001 -b 192.168.25.255 --active_on_finish --mqtt-host=127.0.0.1 -t 3 --mqtt-port=8913 --prime-host=192.168.25.51 --prime-port=80 --prime-port2=6004 --prime-code=4133 --prime-pass=pass >"$FILEOUT" 2>"$FILEERR" &
#/usr/bin/python main.py -c $PTH/devices.xml -s 10001 -b 192.168.25.255 --active_on_finish --mqtt-host=rbx1-fr.quadhost.net --mqtt-port=8913 >$FILEOUT 2>$FILEERR &
#/usr/bin/python main.py -c $PTH/devices.xml -s 10001 -b 192.168.25.255 --active_on_finish >$FILEOUT 2>$FILEERR &
