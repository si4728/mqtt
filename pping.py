import socket
import time
import os
import struct
import json
import configparser
import ssl
from datetime import datetime


config = configparser.ConfigParser()
config.read('ccms.ini')

# 전역 변수 (ini 파일에서 읽음)
MQTT_BROKER = config['MQTT']['broker']
MQTT_PORT = int(config['MQTT']['port'])
MQTT_TOPIC = config['MQTT']['topic']

LOG_FILE = config['LOG']['log_file']
HASH_MISMATCH_LOG = config['LOG']['hash_mismatch_log']
PING_SLEEP = int(config['TEST']['ping_sleep'])


def checksum(source_string):
    """ICMP checksum 계산"""
    sum = 0
    countTo = (len(source_string) // 2) * 2
    count = 0
    while count < countTo:
        thisVal = source_string[count + 1] * 256 + source_string[count]
        sum = sum + thisVal
        sum = sum & 0xffffffff
        count = count + 2
    if countTo < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xffffffff
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def create_packet(id):
    """ICMP Echo Request 패킷 생성"""
    header = struct.pack("bbHHh", 8, 0, 0, id, 1)
    data = struct.pack("d", time.time())
    my_checksum = checksum(header + data)
    header = struct.pack("bbHHh", 8, 0, socket.htons(my_checksum), id, 1)
    return header + data


def do_ping(dest_addr, timeout=10):
    """ICMP Ping - root 권한 필요"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    except PermissionError:
        return None  # root 권한 없으면 실패
    packet_id = os.getpid() & 0xFFFF
    packet = create_packet(packet_id)
    sock.settimeout(timeout)
    start_time = time.time()
    try:
        sock.sendto(packet, (dest_addr, 1))
        sock.recvfrom(1024)
        return (time.time() - start_time) # sec 단위 
    except socket.timeout:
        return None
    finally:
        sock.close()


def socket_time(host, port=443, timeout=10):
    """TCP/SSL 연결 시간 측정"""
    start = time.time()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((host, port))
        tcp_connect_time = (time.time() - start) # sec 단위
        # SSL handshake 시간까지 보려면 아래 사용
        context = ssl.create_default_context()
        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        #print(f"TCP Connection Time:{host} = {tcp_connect_time:.4f} sec.")


        ssl_sock.close()
        return tcp_connect_time
    except Exception as e:
        print(f"[ERROR] TCP connection fail {host}:{port} - {e}")
        return None
    finally:
        sock.close()


def average_ping(host, count=5):
    """평균 Ping (ICMP 우선, 안되면 TCP)"""
    print(f"[INFO] Checking {host}")
    times = []

    for _ in range(count):
        delay = do_ping(host)
        if delay is not None:
            times.append(delay)
        else:
            #print(f"[WARN] ICMP ping failed for {host}, trying TCP...")
            # ICMP 실패 → TCP 연결 시간 사용
            tcp_delay = socket_time(host)
            if tcp_delay is not None:
                times.append(tcp_delay)
        time.sleep(0.5)

    if times:
        return sum(times) / len(times)
    else:
        return -1


def timing_logging(mdata):
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(mdata) + "\n")

if __name__ == '__main__':
    while True:
        tcp_ping = average_ping(MQTT_BROKER)
        print(f"[RESULT] {MQTT_BROKER} ping = {tcp_ping:.6f} ms")

        meta = {
            "ping_ms": tcp_ping,
            "broker": MQTT_BROKER,
            "timestamp": datetime.now().isoformat()
        }

        timing_logging(meta)

        time.sleep(PING_SLEEP)
