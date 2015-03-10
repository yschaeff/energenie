#!/usr/bin/env python3

from sys import argv, exit
from time import sleep, time as now
from collections import namedtuple
import socket

Energenie = namedtuple('Energenie', "ip port pwd")
Measurement = namedtuple('Measurement', "current voltage power usage")

#######################
## Start user config ##
#######################
genies = [
	##         IP-address       port   password ##
	Energenie("10.0.0.1", 5000, "00000000"),
	Energenie("10.0.0.2", 5000, "00000000")
]

RETRIES = 3
TIMEOUT = 1
#####################
## End user config ##
#####################

START = 0x11

def hex(data):    return " ".join(map(lambda x: "%02x"%x, dec(data)))
def enc(data): return "".join(map(chr, data))
def dec(data): return map(ord, data)

def b_end(l):
	return reduce(lambda x, y: (x<<8)|y, l)
def l_end(l):
	l.reverse()
	return reduce(lambda x, y: (x<<8)|y, l)

def authenticate(nonce, key):
	n = dec(nonce)
	k = dec(key)
	v1 = ((n[0]^k[2]) * k[0]) ^ (k[6] | (k[4]<<8)) ^ n[2];
	v2 = ((n[1]^k[3]) * k[1]) ^ (k[7] | (k[5]<<8)) ^ n[3];
	return enc([v1&0xFF, v1>>8, v2&0xFF, v2>>8])

def decrypt(nonce, password, ciphertext):
	l = len(ciphertext)
	m = dec(nonce)
	p = dec(password)
	c = dec(ciphertext)
	return enc(map(lambda i: ((((c[(l-1)-i]-p[1])^p[0])-m[3])^m[2]) & 0xFF, range(l)))

def crypt(nonce, password, plaintext):
	l = len(plaintext)
	m = dec(nonce)
	p = dec(password)
	c = dec(plaintext)
	return enc(map(lambda i: ((((c[(l-1)-i]^m[2])+m[3])^p[0])+p[1]) & 0xFF, range(l)))
	
def get_data(s, pwd):
	s.send(enc([START]))
	nonce = s.recv(4)
	nonce_response = authenticate(nonce, pwd)
	s.send(nonce_response)
	statcrypt = s.recv(4)
	statplain = decrypt(nonce, pwd, statcrypt)
	n = int(now())
	t = [n&0xFF, (n>>8)&0xFF, (n>>16)&0xFF, (n>>24)&0xFF]
	request1_plain = "\x04"*4 + enc([0x64] + t + [0x00]*5) #14 bytes
	request1_crypt = crypt(nonce, pwd, "\x04"*4) + enc([0x64] + t + [0x00]*5)
	s.send(request1_crypt)
	response1_crypt = s.recv(4)
	response1_plain = decrypt(nonce, pwd, response1_crypt)
	request2_plain = "\x00"*44
	request2_crypt = crypt(nonce, pwd, request2_plain)
	s.send(request2_crypt)
	response2_crypt = s.recv(41)
	response2_plain = decrypt(nonce, pwd, response2_crypt)
	request3_plain = "\x01\x02\x03\x04" # can be anything
	request3_crypt = crypt(nonce, pwd, request3_plain)
	s.send(request3_crypt)
	response3_plain = s.recv(43)

	msg = {}
	msg["0_start"] = enc([START])
	msg["1_nonce"] = nonce
	msg["2_nonce_response"] = nonce_response
	msg["3_status_crypt"] = statcrypt
	msg["3_status_plain"] = statplain
	msg["4_request1_plain"] = request1_plain
	msg["4_request1_crypt"] = request1_crypt
	msg["5_response1_crypt"] = response1_crypt
	msg["5_response1_plain"] = response1_plain
	msg["6_request2_plain"] = request2_plain
	msg["6_request2_crypt"] = request2_crypt
	msg["7_response2_crypt"] = response2_crypt
	msg["7_response2_plain"] = response2_plain
	msg["8_request3_crypt"] = request3_crypt
	msg["8_request3_plain"] = request3_plain
	msg["9_response3_plain"] = response3_plain

	return msg

def graph_order(base):
	g = ["%s%d" % (base, i+1) for i in range(len(genies))]
	return " ".join(["graph_order"]+g)
def label(base):
	m = ["%s%d.label meter%d"%(base, i+1, i+1) for i in range(len(genies))]
	return "\n".join(m)
def warning(base, lvl):
	m = ["%s%d.warning %d"%(base, lvl) for i in range(len(genies))]
	return "\n".join(m)
def critical(base, lvl):
	m = ["%s%d.critical %d"%(base, lvl) for i in range(len(genies))]
	return "\n".join(m)

if len(argv) > 1 and argv[1] == "autoconf":
	print "yes"
	exit(0)

elif len(argv) > 1 and argv[1] == "config":
	print "multigraph e.x"
	print "graph_title Energy used"
	print graph_order("usage")
	print "graph_category Power"
	print "graph_vlabel usage (kWh)"
	print "graph_scale yes"
	print "graph_info Accumulated energy usage in kWh"
	print label("usage")
	print "multigraph w.x"
	print "graph_title Power"
	print graph_order("power")
	print "graph_category Power"
	print "graph_vlabel Power (W)"
	print "graph_scale yes"
	print "graph_info Work in Watt"
	print label("power")
	print "multigraph v.x"
	print "graph_title Voltage"
	print graph_order("volt")
	print "graph_category Power"
	print "graph_vlabel Voltage (V)"
	print "graph_scale yes"
	print "graph_info Measured voltage over power supply"
	print label("volt")
	print "multigraph c.x"
	print "graph_title Current"
	print graph_order("current")
	print "graph_category Power"
	print "graph_vlabel Current (A)"
	print "graph_scale yes"
	print "graph_info Current drawn in Ampere"
	print warning("current", 9)
	print critical("current", 10)
	print label("current")
	exit(0)

def collect(genie):
	for i in range(RETRIES):
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.settimeout(TIMEOUT/2.0) #timeout to detect failure
			s.connect((genie.ip, genie.port))
			msg = get_data(s, genie.pwd)
			s.close()
			e = dec(msg["9_response3_plain"])
			current     = b_end(e[4:7])
			voltage     = b_end(e[7:10])
			power       = b_end(e[10:13])
			accumulated = b_end(e[14:18])
			return Measurement(current, voltage, power, accumulated)
		except socket.timeout:
			sleep(TIMEOUT)
	return None

msgs = [collect(genie) for genie in genies]

print "multigraph e.x"
for i, msg in enumerate(msgs):
	if msg:
		print "usage%d.value %f" % (i+1, msg.usage/20000.0)

print "multigraph w.x"
for i, msg in enumerate(msgs):
	if msg:
		print "power%d.value %f" % (i+1, msg.power/466.0)

print "multigraph v.x"
for i, msg in enumerate(msgs):
	if msg:
		print "volt%d.value %f" % (i+1, msg.voltage/37300.0)

print "multigraph c.x"
for i, msg in enumerate(msgs):
	if msg:
		print "current%d.value %f" % (i+1, msg.current/420000.0)
