import pyshark
import csv
import threading
import msvcrt
import requests
import json
import socket
from datetime import datetime


# 检测字符串是否是ipv4地址
def is_ipv4_address(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        return False

# 设置数据包源ip
src_ip = '192.168.137.28'

# 获取本地ip
local_ips = []
local_ip = socket.gethostbyname_ex(socket.gethostname())
for i in local_ip:
    for j in i:
        if is_ipv4_address(j):
            local_ips.append(j)
result = " or dst host ".join(local_ips)

# 创建一个抓包对象来从interface指定的网络抓包
capture = pyshark.LiveCapture(interface='本地连接* 10',
                              bpf_filter=f'udp and src host {src_ip} and not (dst host {result})')

# 创建一个DataFrame来存储目标ip地址和归属地
dest_ips = []

# 从文件加载黑名单，没有文件时创建黑名单
try:
    with open('黑名单.csv', 'r', newline='') as f:
        reader = csv.reader(f)
        blacklist = list(reader)
except FileNotFoundError:
    blacklist = [['对手IP', 'IP归属地']]

# 从文件加载一起玩过的人的历史，没有文件时创建
try:
    with open('一起玩的人.csv', 'r', newline='') as f:
        reader = csv.reader(f)
        comp_ips = list(reader)
except FileNotFoundError:
    comp_ips = [['时间', '对手IP', 'IP归属地']]

# 创建一个flag来决定抓包是否继续
continue_capture = True

# 调用api获取归属地
ip_location_cache = {}
def get_ip_location(ip):
    global ip_location_cache
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

# 把DataFrame保存为csv文件
def save():
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

# 监听用户输入
def check_user_input():
    global continue_capture, blacklist, comp_ips, dest_ips, dest_ip2, comp_ip, comp_ip2, comp_ip3, flag

    while continue_capture:
        if msvcrt.kbhit():
            key = msvcrt.getch()
            if key == b'q':  # 按Q终止抓包
                continue_capture = False
                print('已停止抓包')
            elif key == b'b':  # 按B将当前ip加入黑名单
                if len(comp_ips) > 1:
                    last_dest_ip = comp_ips[-1][1]
                    location = get_ip_location(last_dest_ip)
                    blacklist.append([last_dest_ip, location])
                    print(f'已将位于 \033[34m{location}\033[0m 的 \033[32m{last_dest_ip}\033[0m 添加至黑名单')
                else:
                    print('暂未捕获到任何对手IP')
            elif key == b's':  # 按S保存列表
                save()

# 新建线程开始监听用户输入
t = threading.Thread(target=check_user_input)
t.start()

dest_ip2 = None
comp_ip = None
comp_ip2 = None
comp_ip3 = None

# 抓包处理函数
def process_packet(packet):
    global continue_capture, comp_ip, comp_ip2, comp_ip3, comp_ips, flag, dest_ip, dest_ip2, dest_ips

    # 检查是否继续抓包
    if not continue_capture:
        return False  # 停止抓包

    # 从包中获取目标ip地址
    dest_ip = packet.ip.dst

    # 过滤亚马逊服务器的地址
    if "亚马逊" not in get_ip_location(packet.ip.dst):
        comp_ip = packet.ip.dst

    # 检查目标ip是否在黑名单中
    if comp_ip in [row[0] for row in blacklist]:
        if comp_ip != comp_ip3:
            comp_ip3 = comp_ip
            flag = True
        if flag:
            print(
                f'\033[33m来自 \033[34m{get_ip_location(comp_ip)}\033[33m 的 \033[32m{comp_ip} \033[33m在黑名单中，尽快手动拔线！\033[0m')
            flag = False

    # 如果前后两个ip不一致，展示当前时间、目标ip和归属地
    if dest_ip != dest_ip2:
        current_time = datetime.now().strftime('%Y年%m月%d日 - %H:%M:%S')
        print(f'{current_time} \033[32m{dest_ip}\033[0m \033[34m{get_ip_location(dest_ip)}\033[0m')
        dest_ip2 = dest_ip
        location = get_ip_location(dest_ip)
        dest_ips.append([current_time, dest_ip, location])

    # 记录对手ip
    if comp_ip != comp_ip2:
        comp_current_time = datetime.now().strftime('%Y年%m月%d日 - %H:%M:%S')
        comp_ip2 = comp_ip
        comp_location = get_ip_location(comp_ip)
        print(f'遇到对手 \033[32m{comp_ip}\033[0m')
        comp_ips.append([comp_current_time, comp_ip, comp_location])


# 对每个包应用回调函数
capture.apply_on_packets(process_packet)

# 保存列表
save()
