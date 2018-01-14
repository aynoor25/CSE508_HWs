from scapy.all import *
import sys
import getopt
import socket
import fcntl
import struct
from datetime import datetime

interface = 'en0'
traceFile = None
bpf = ''
seenResponses = {}

# Function help taken from: http://www.cs.dartmouth.edu/~sergey/netreads/local/reliable-dns-spoofing-with-python-scapy-nfqueue.html#selection-813.9-1157.2
# https://null-byte.wonderhowto.com/how-to/build-dns-packet-sniffer-with-scapy-and-python-0163601/
def dns_detect(packet):
	if IP in packet:
		if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
			seenResponses[packet[DNS].id] = None
		elif packet.haslayer(DNS) and packet.getlayer(DNS).qr == 1:
			if seenResponses[packet[DNS].id] == None:
				seenResponses[packet[DNS].id] = [packet[IP].payload, packet[DNSRR].rdata]
			elif seenResponses[packet[DNS].id][0] == packet[IP].payload:
				print "Retransmission Occurred"
				seenResponses[packet[DNS].id].append(packet[DNSRR].rdata)
			else:
				print datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "DNS poisoning attempt\n", "TXID ", str(packet[DNS].id), " Request ", packet[DNS].qd.qname, "\n", "Answer1 ", str(packet[DNSRR].rdata), " Answer 2 ", str(seenResponses[packet[DNS].id][1:])
				print "================================================================="
				# remove this entry from seenResponses as for a new query it should start from initial state i.e no IP seen
				del seenResponses[packet[DNS].id]

def main():
	global interface, traceFile, bpf, seenResponses
	try:
		opts, args = getopt.getopt(sys.argv[1:], 'i:r:')
	except getopt.GetoptError, e:
		print e

	for opt, arg in opts:
		if opt == '-i':
			interface = arg
		if opt == '-r':
			traceFile = arg

	if len(args) == 1:
		bpf = args[0]
	elif len(args) > 1:
		print "Usage: \n dnsinject [-i interface] [-r tracefile] expression"
	else:
		bpf = 'udp port 53'

	print interface, traceFile, bpf
	if traceFile == None:
		try:
			sniff(iface = interface, filter = bpf, prn = dns_detect, store = 0)
		except Exception,e:
			print "Exception while sniffing", e
	else:
		try:
			sniff(offline = traceFile, filter = bpf, prn = dns_detect, store = 0)
		except Exception,e:
			print "Exception while sniffing", e

main()