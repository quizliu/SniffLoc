import requests
from scapy.all import *

pkts = sniff(iface = "en0", count = 0, timeout = 10)
msg_list = []
for i in pkts:
	msg = hexdump(i, dump=True)
	msg_list.append(msg)

target = "02 00 48"  # QQ语音电话数据包的协议是UDP，报文头020048
ip_list = set()
for i in range(len(msg_list)):
	if target in msg_list[i]:
		print("Found {0}. src IP address: {1}. dst IP address: {2}".format(i, pkts[i][IP].src, pkts[i][IP].dst))
		ip_list.add(pkts[i][IP].src)
		ip_list.add(pkts[i][IP].dst)

for i in ip_list:
	if i.startswith("192") or i.startswith("10"):
		continue
	else:
		print("target IP address:", i)
		target_IP = i
		break

url = "https://api.ip138.com/ipv4/"
headers = {"token": "36c95a5a6076c5700425129ca7f23f98"}
params = {'ip': target_IP, 'datatype': 'jsonp', 'callback': 'find'}
response = requests.get(url = url, params = params, headers = headers)
print(response.text)
