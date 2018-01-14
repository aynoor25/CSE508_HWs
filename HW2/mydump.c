#include <ctype.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#define ETH_HEADER 14

char * str;
int sflag;
struct eth_header{
	const struct ether_addr dest_addr;
	const struct ether_addr src_addr;
	u_short type;
};

struct ip_header {
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service 
    u_short tlen;           // Total length 
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short checksum;       // Header checksum
    struct in_addr  saddr;      // Source address
    struct in_addr  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
};

/* TCP header */
typedef u_int tcp_seq;

struct tcp_header {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
        u_char  th_flags;
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* UDP header */
struct udp_header {
        u_short sport;               /* source port */
        u_short dport;               /* destination port */
		u_short length;
		u_short checksum;
};


// function taken from sniffex.c but a fairly easy function to write
void print_hex_ascii_line(const u_char *payload, int len)
{

	int i;
	int gap;
	const u_char *ch;	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}
// function taken from sniffex.c but a fairly easy function to write
void print_payload(const u_char *payload, int len) {

	int len_rem = len;
	int line_width = 24;			/* number of bytes per line */
	int line_len;
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem);
			break;
		}
	}

	return;
}

void callback(u_char *arg, const struct pcap_pkthdr* header, const u_char* packet) {
	const char *payload;
	char time[20];
	const struct eth_header *eth;
	const struct ip_header *ip;
	const struct tcp_header *tcp;
	const struct udp_header *udp;
	int ipheadersize, size_payload;
	strftime(time, 20, "%Y-%m-%d %H:%M:%S ", localtime(&header->ts.tv_sec));
	eth=(struct eth_header*)packet;
	ip = (struct ip_header*)(packet+ETH_HEADER);
	ipheadersize=(((ip)->ver_ihl) & 0x0f) *4;


	payload = (u_char *)(packet + ETH_HEADER + ipheadersize );
	size_payload = ntohs(ip->tlen) - ipheadersize;

	int packet_len = ETH_HEADER + header->len;
	u_short sport = NULL;
	u_short dport = NULL;
	char *protocol_type[4] =  {"TCP", "UDP", "ICMP", "IP"};
	int protocol_type_index = -1;
	char *mac_src_addr = ether_ntoa(&eth->src_addr);
	char *mac_dst_addr = ether_ntoa(&eth->dest_addr);
	char *ip_src       = inet_ntoa(ip->saddr);
	char *ip_dst      = inet_ntoa(ip->daddr);

	switch (ip->proto) {
		case IPPROTO_TCP:
			tcp = (struct tcp_header*)(packet+ETH_HEADER+ipheadersize);
			sport = ntohs(tcp->th_sport);
			dport = ntohs(tcp->th_dport);
			protocol_type_index = 0;
			break;
		case IPPROTO_UDP:
			protocol_type_index = 1;
			udp = (struct udp_header*)(packet+ETH_HEADER+ipheadersize);
			sport = ntohs(udp->sport);
			dport = ntohs(udp->dport);
			break;
		case IPPROTO_ICMP:
			protocol_type_index = 2;
			break;
		case IPPROTO_IP:
			protocol_type_index = 3;
			break;
		default:
		break;
	}

	printf("Time: %s ", time);
	printf("Source MAC address: %s ", ether_ntoa(&eth->src_addr));
	printf("Destination MAC address %s ", ether_ntoa(&eth->dest_addr));
	printf("Ethernet Type: %d ", eth->type);
	printf("Length: %d %d ", packet_len, header->len);

	if (sport != NULL && dport != NULL) {
		printf("%s: ", inet_ntoa(ip->saddr));
		printf("%d -> ", sport);
		printf("%s: ", inet_ntoa(ip->daddr));
		printf("%d ", dport);
		// printf("Time: %s Source MAC address: %s Destination MAC address: %s Ethernet Type: %d Length: %d %s:%d -> %s:%d Protocol Type: %s \n", time, mac_src_addr, mac_dst_addr,  eth->type, packet_len, ip_src, sport, ip_dst, dport, protocol_type[protocol_type_index]);
	} else {
		printf("%s\n", inet_ntoa(ip->saddr));
		printf("%s\n", inet_ntoa(ip->daddr));
		// printf("Time: %s Source MAC address: %s Destination MAC address: %s Ethernet Type: %d Length: %d %s -> %s Protocol Type: %s \n", time, mac_src_addr, mac_dst_addr,  eth->type, packet_len, ip_src, ip_dst, protocol_type[protocol_type_index]);
	}
	printf("Protocol Type: %s \n", protocol_type[protocol_type_index]);
	if (sflag==1 && strstr(payload,str)!=NULL){
		print_payload(payload, size_payload);
	}
	else if (sflag==0){
		print_payload(payload, size_payload);
	}	
}



int main(int argc, char *argv[]) {
	char *ivalue = NULL, *rvalue = NULL, *svalue = NULL;
	int gflag = 0, rflag = 0, c, index;

	pcap_t *handle;						/* Session handle */
	char *dev;							/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];		/* Error string */
	struct bpf_program fp;				/* The compiled filter */
	char* filter_exp =NULL;				/* The filter expression */
	bpf_u_int32 mask;					/* Our netmask */
	bpf_u_int32 net;					/* Our IP */
	struct pcap_pkthdr header;			/* The header that pcap gives us */
	const u_char *packet;				/* The actual packet */

	// get user options
	sflag=0;
	while ((c = getopt (argc, argv, "i:r:s:")) != -1){
		switch (c){
		case 'i':
			ivalue = optarg; break;
		case 'r':
			rflag=1; rvalue = optarg; break;
		case 's':
			sflag=1; svalue = optarg; break;
		default:
			exit(-2);
		}
	}
	printf("interface = %s , file = %s, string = %s \n", ivalue, rvalue, svalue);
	// get expression value if it exists
	for (index = optind; index < argc; index++) {
		filter_exp = argv[index];
	}
	printf("Expression filter: %s \n", filter_exp);

	/* Define the device */
	if (ivalue!=NULL) {
		dev = ivalue;
	} else {
		dev = pcap_lookupdev(errbuf);
	}
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* network number and mask associated with the device/interface */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	// We have device / file we can start capturing
	if (rflag==1) {
		handle= pcap_open_offline(rvalue,errbuf);
	} else {
		handle= pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
	}

	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return (2);
	}

	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	str=svalue;
	/* Start capturing */
	pcap_loop(handle, -1, callback, NULL);
	/* And close the session */
	pcap_close(handle);


	return(0);
}