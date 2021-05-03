nohup python3.9 /root/test/waitress_server.py > /root/test/log.txt 2>&1 &
echo $! > /root/save_pid.txt
