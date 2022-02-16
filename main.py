import json
import tkinter as tk
import requests
from scapy.all import *


def shutdown(gui, msg):
	gui.output.set(msg)
	gui.on_hit = False
	return


def update_window(gui, msg, var):
	var.set(msg)
	gui.window.update()  # This forces the window to update
	time.sleep(1)
	return


def sniffing(gui, timeout=10):
	msg = "sniffing for {} seconds...".format(timeout)
	update_window(gui, msg, gui.output)
	pkts = sniff(iface="en0", count=0, timeout=timeout)
	msg_list = []
	for i in pkts:
		msg = hexdump(i, dump=True)
		msg_list.append(msg)
	gui.packets, gui.messages = pkts, msg_list
	return


def filtering(pkts, msg_list, gui):
	msg = "filtering..."
	update_window(gui, msg, gui.output)
	target = "02 00 48"  # UDP, 020048
	ip_list = set()
	for i in range(len(msg_list)):
		if target in msg_list[i]:
			# print("Found {0}. src IP address: {1}. dst IP address: {2}".format(i, pkts[i][IP].src, pkts[i][IP].dst))
			ip_list.add(pkts[i][IP].src)
			ip_list.add(pkts[i][IP].dst)
	gui.ips = ip_list
	return


def find_ip(ip_list, gui):
	msg = "finding ip..."
	update_window(gui, msg, gui.output)
	for i in ip_list:
		if i.startswith("192") or i.startswith("10"):
			continue
		else:
			# print("target IP address:", i)
			gui.target_ip = i
			break
	if not gui.target_ip:
		msg = 'no available ip address. please try again.'
		shutdown(gui, msg)
	return


def geolocation(ip, gui, country):
	if not ip:
		return
	msg = "locating..."
	update_window(gui, msg, gui.output)
	response = None
	if country == "cn":
		url = "https://api.ip138.com/ipv4/"
		headers = {"token": "36c95a5a6076c5700425129ca7f23f98"}
		payload = {'ip': ip, 'datatype': 'jsonp', 'callback': 'find'}
		response = requests.get(url=url, params=payload, headers=headers)
	elif country == "us":
		url = "http://api.ipstack.com/{}".format(ip)
		payload = {"access_key": "df15861d1c22de3daf380e1d340ae51f"}
		response = requests.get(url=url, params=payload)
	# print(response.url)
	gui.response = response
	return


def parse_response(text, country):
	if country == 'us':
		text = text.replace('false', 'False')
		text = text.replace('true', 'True')
		source = eval(text)
		info = {'ip', 'country_name', 'region_name', 'city', 'latitude', 'longitude'}
		source = {k: v for k, v in source.items() if k in info}
	elif country == 'cn':
		text = text[5:-1]
		source = eval(text)
		info = {'ip', 'data'}
		source = {k: v for k, v in source.items() if k in info}
		source['data'] = ', '.join(i for i in source['data'] if i)
	json_str = json.dumps(source, ensure_ascii=False, indent=4)
	return json_str


class GUI:
	def __init__(self):
		self.window = tk.Tk()
		self.window.title("SniffLoc")
		self.window.geometry('600x480')
		self.output = tk.StringVar()  # show messages
		self.result = tk.StringVar()  # show results if success
		self.info = tk.StringVar()  # info for country update
		self.label1 = tk.Label(self.window, textvariable=self.output,
							   bg='#E74C3C', fg='black', font=('Arial', 18), width=50, height=2)
		self.label2 = tk.Label(self.window, textvariable=self.result, bg='#28B463', fg='black', font=('Arial', 18),
							   width=50,
							   height=10)
		self.label3 = tk.Label(self.window, textvariable=self.info, bg='#3498DB', fg='black', font=('Arial', 18),
							   width=20,
							   height=2)
		self.button = tk.Button(self.window, text='click to start', font=('Arial', 18), width=10, height=1,
								command=self.backend, activebackground='red')
		self.button_country_us = tk.Button(self.window, text='US', font=('Arial', 18), width=10, height=1,
										   command=lambda: self.callback_country('us'), activeforeground="red")
		self.button_country_cn = tk.Button(self.window, text='CN', font=('Arial', 18), width=10, height=1,
										   command=lambda: self.callback_country('cn'), activeforeground='red')
		self.label1.pack()
		self.label2.pack()
		self.label3.pack()
		self.button.pack()
		self.button_country_us.pack()
		self.button_country_cn.pack()

		self.button_country_us.place(x=70, y=350)
		self.button_country_cn.place(in_=self.button_country_us, rely=1, relx=-0.01)
		self.label3.place(x=320, y=350)

		self.on_hit = False  # lock all buttons while backend running

		self.packets = None
		self.messages = None
		self.ips = None
		self.target_ip = None
		self.response = None
		self.country = 'us'

	def callback_country(self, string):
		if not self.on_hit:
			self.on_hit = True
			self.country = string
			update_window(self, f'using conutry API: {string}', self.info)
			self.on_hit = False

	def backend(self):
		if not self.on_hit:
			self.on_hit = True
			update_window(self, '', self.result)
			sniffing(self)  # TODO: add timeout from button
			filtering(self.packets, self.messages, self)
			find_ip(self.ips, self)
			geolocation(self.target_ip, self, self.country)
			if self.response:
				json_response = parse_response(self.response.text, self.country)
				update_window(self, json_response, self.result)
				update_window(self, 'success!', self.output)
				self.response = None
				self.packets = self.messages = self.ips = self.target_ip = None
			else:
				update_window(self, 'fail!', self.output)
				update_window(self, 'sniff failed or no data, please try again!', self.result)
				self.response = None
		self.on_hit = False
		return


def main():
	gui = GUI()
	gui.window.mainloop()


if __name__ == "__main__":
	main()
