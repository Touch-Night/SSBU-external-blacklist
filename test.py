import pyshark
import csv
import threading
import msvcrt
import requests
import json
import socket
from datetime import datetime


def is_ipv4_address(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        return False


def get_ip_location(ip, ip_location_cache):
    if ip in ip_location_cache:
        return ip_location_cache[ip]
    else:
        url = f"https://api.vore.top/api/IPdata?ip={ip}"
        response = requests.get(url)
        data = json.loads(response.text)
        if data["code"] == 200:
            location = data["adcode"]["o"]
            ip_location_cache[ip] = location
            return location
        else:
            return "错误：无法解析归属地"


def save(dest_ips, blacklist, comp_ips):
    with open('latest_log.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(dest_ips)

    with open('黑名单.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(blacklist)

    with open('一起玩的人.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(comp_ips)
    print('已保存所有列表')


def check_user_input(continue_capture, comp_ips, dest_ips, blacklist, ip_location_cache):
    dest_ip2, comp_ip, comp_ip2, comp_ip3 = None, None, None, None

    while continue_capture:
        if msvcrt.kbhit():
            key = msvcrt.getch()
            if key == b'q':  # 按Q终止抓包
                continue_capture = False
                print('已停止抓包')
            elif key == b'b':  # 按B将当前ip加入黑名单
                if len(comp_ips) > 1:
                    last_dest_ip = comp_ips[-1][1]
                    location = get_ip_location(last_dest_ip, ip_location_cache)
                    blacklist.append([last_dest_ip, location])
                    print(f'已将位于 \033[34m{location}\033[0m 的 \033[32m{last_dest_ip}\033[0m 添加至黑名单')
                else:
                    print('暂未捕获到任何对手IP')
            elif key == b's':  # 按S保存列表
                save(dest_ips, blacklist, comp_ips)

    return continue_capture, dest_ips, blacklist, comp_ips, dest_ip2, comp_ip, comp_ip2, comp_ip3


def process_packet(packet, continue_capture, comp_ip, comp_ip2, comp_ip3, comp_ips, dest_ip, dest_ip2, dest_ips, ip_location_cache, blacklist):
    if not continue_capture:
        return False, None, None, None, None, None, None, None, None

    dest_ip = packet.ip.dst
    if "亚马逊" not in get_ip_location(packet.ip.dst, ip_location_cache):
        comp_ip = packet.ip.dst

    if comp_ip in [row[0] for row in blacklist]:
        if comp_ip != comp_ip3:
            comp_ip3 = comp_ip
            print(
                f'\033[33m来自 \033[34m{get_ip_location(comp_ip, ip_location_cache)}\033[33m 的 \033[32m{comp_ip} \033[33m在黑名单中，尽快手动拔线！\033[0m')

    if dest_ip != dest_ip2:
        current_time = datetime.now().strftime('%Y年%m月%d日 - %H:%M:%S')

        dest_ip2 = dest_ip
        location = get_ip_location(dest_ip, ip_location_cache)
        print(f'{current_time} \033[32m{dest_ip}\033[0m \033[34m{location}\033[0m')
        dest_ips.append([current_time, dest_ip, location])

    if comp_ip != comp_ip2:
        comp_current_time = datetime.now().strftime('%Y年%m月%d日 - %H:%M:%S')
        comp_ip2 = comp_ip
        location = get_ip_location(comp_ip, ip_location_cache)
        print(f'{comp_current_time} \033[32m{comp_ip}\033[0m \033[34m{location}\033[0m')
        comp_ips.append([comp_current_time, comp_ip, location])

    return continue_capture, comp_ip, comp_ip2, comp_ip3, comp_ips, dest_ip, dest_ip2, dest_ips, ip_location_cache


def main():
    cap = pyshark.LiveCapture(interface='本地连接* 10', bpf_filter='udp and src host 192.168.137.28')

    dest_ips = [['时间', 'IP', '归属地']]
    comp_ips = [['时间', 'IP', '归属地']]
    blacklist = [[row[0], row[1]] for row in csv.reader(open('黑名单.csv', 'r'))]
    ip_location_cache = {}

    dest_ip, dest_ip2, comp_ip, comp_ip2, comp_ip3 = None, None, None, None, None

    continue_capture = True

    # Start the user input checking thread
    threading.Thread(target=check_user_input, args=(continue_capture, comp_ips, dest_ips, blacklist, ip_location_cache)).start()

    try:
        for packet in cap.sniff_continuously():
            if 'IP' in packet:
                continue_capture, comp_ip, comp_ip2, comp_ip3, comp_ips, dest_ip, dest_ip2, dest_ips, ip_location_cache = process_packet(
                    packet, continue_capture, comp_ip, comp_ip2, comp_ip3, comp_ips, dest_ip, dest_ip2, dest_ips, ip_location_cache, blacklist)

                if not continue_capture:
                    break
    except KeyboardInterrupt:
        print('已停止抓包')

    save(dest_ips, blacklist, comp_ips)


if __name__ == '__main__':
    main()
