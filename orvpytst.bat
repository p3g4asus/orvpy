pushd %~dp0
call venv\Scripts\activate
copy /Y devices.xml d.tst.xml
REM ~ py -2 src/main.py -c "d.tst.xml" --tcpport=10001 --httpport=10002 -b 192.168.25.255 --active_on_finish --mqtt-host=192.168.25.20 -t 3 --mqtt-port=8913 --prime-host=192.168.25.51 --prime-port=80 --prime-port2=6004 --prime-code=4133 --prime-pass=pass > err_out.txt 2>&1
set MAINPTH=%~dp0

python src/main.py -c "d.tst.xml" -s 10001 -g 10002 -p 10000 -b 192.168.25.255 --active_on_finish --mqtt-host=192.168.25.4 -t 3 --mqtt-port=8913 --prime-host=192.168.25.51 --prime-port=80 --prime-port2=6004 --prime-code=4133 --prime-pass=pass
pause