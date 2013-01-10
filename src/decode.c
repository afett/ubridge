/*
 * UBridge: decode source
 *	By Benjamin Kittridge. Copyright (C) 2012, All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <time.h>
#include <arpa/inet.h>
#include <ctype.h>
#define __FAVOR_BSD
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "decode.h"

////////////////////////////////////////////////////////////////////////////////
// Class:       trace
// Description: Packet capturing system

////////////////////////////////////////////////////////////////////////////////
// Section:     Global variables

static int (*q_decode_func)(uint8_t *buf, uint32_t len);

////////////////////////////////////////////////////////////////////////////////
// Section:     Decode

void q_decode_parse(uint8_t *buf, uint32_t len) {
	int ret;

	q_decode_func = q_decode_pkt;
	while (len >= 0) {
		if (!q_decode_func)
			break;
		ret = q_decode_func(buf, len);
		buf += ret;
		len -= ret;
	}

	printf("\n");
}

int q_decode_pkt(uint8_t *buf, uint32_t len) {
	struct timeval tv;
	struct timezone tvp;
	struct tm tm;

	gettimeofday(&tv, &tvp);
	localtime_r(&tv.tv_sec, &tm);

#ifdef Q_DECODE_CONF_SHORT
	printf("%02d:%02d:%02d.%06"PRIu64" ",
		tm.tm_hour, tm.tm_min, tm.tm_sec, (uint64_t)tv.tv_usec);
#else
	printf("PKT:   [ len=%d time=%02d:%02d:%02d.%06"PRIu64" ]\n",
		len, tm.tm_hour, tm.tm_min, tm.tm_sec, (uint64_t)tv.tv_usec);
#endif

	q_decode_func = q_decode_eth;
	return 0;
}

int q_decode_eth(uint8_t *buf, uint32_t len) {
	struct ethhdr *eth;

	eth = (struct ethhdr*)buf;
	if (len < sizeof(*eth)) {
		q_decode_func = q_decode_data;
		return 0;
	}

#ifndef Q_DECODE_CONF_SHORT
	printf("ETH:   [ dest=%02x:%02x:%02x:%02x:%02x:%02x "
		"source=%02x:%02x:%02x:%02x:%02x:%02x proto=%d ]\n",
		eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
		eth->h_dest[3], eth->h_dest[4], eth->h_dest[5],
		eth->h_source[0], eth->h_source[1], eth->h_source[2],
		eth->h_source[3], eth->h_source[4], eth->h_source[5],
		htons(eth->h_proto));
#endif

	switch (htons(eth->h_proto)) {
		case ETH_P_IPV6:
			q_decode_func = q_decode_ipv6;
			break;
			
		case ETH_P_ARP:
			q_decode_func = q_decode_arp;
			break;
			
		case ETH_P_IP:
			q_decode_func = q_decode_ipv4;
			break;
			
		default:
			q_decode_func = q_decode_data;
			break;
	}
	return sizeof(*eth);
}

int q_decode_arp(uint8_t *buf, uint32_t len) {
	struct arphdr *arp;
	char *op;

	arp = (struct arphdr*)buf;
	if (len < sizeof(*arp)) {
		q_decode_func = q_decode_data;
		return 0;
	}

	switch (htons(arp->ar_op)) {
		case ARPOP_REQUEST:	op = "REQUEST";   break;
		case ARPOP_REPLY:	op = "REPLY";     break;
		case ARPOP_RREQUEST:	op = "RREQUEST";  break;
		case ARPOP_RREPLY:	op = "RREPLY";    break;
		case ARPOP_InREQUEST:	op = "InREQUEST"; break;
		case ARPOP_InREPLY:	op = "InREPLY";   break;
		case ARPOP_NAK:		op = "NAK";       break;
		default:		op = "UNKNOWN";   break;
	}
	
#ifdef Q_DECODE_CONF_SHORT
	printf("ARP %d,%d > %d,%d > %s(%d) ",
		htons(arp->ar_hrd), arp->ar_hln,
		htons(arp->ar_pro), arp->ar_pln,
		op, htons(arp->ar_op));
#else
	printf("ARP:   [ hard=%d hard_len=%d proto=%d proto_len=%d op=%s(%d) ]\n",
		htons(arp->ar_hrd), arp->ar_hln,
		htons(arp->ar_pro), arp->ar_pln,
		op, htons(arp->ar_op));
#endif

	if (htons(arp->ar_hrd) == ARPHRD_ETHER && arp->ar_hln == ETH_ALEN &&
	    htons(arp->ar_pro) == ETH_P_IP && arp->ar_pln == sizeof(in_addr_t))
		q_decode_func = q_decode_arp_eth_ip;
	else
		q_decode_func = q_decode_data;
	return sizeof(*arp);
}

int q_decode_arp_eth_ip(uint8_t *buf, uint32_t len) {
	struct arpeihdr *arpei;

	arpei = (struct arpeihdr*)buf;
	if (len < sizeof(*arpei)) {
		q_decode_func = q_decode_data;
		return 0;
	}

#ifdef Q_DECODE_CONF_SHORT
	printf("%02x:%02x:%02x:%02x:%02x:%02x (%d.%d.%d.%d) -> "
		"%02x:%02x:%02x:%02x:%02x:%02x (%d.%d.%d.%d)",
		arpei->src_mac[0], arpei->src_mac[1], arpei->src_mac[2],
		arpei->src_mac[3], arpei->src_mac[4], arpei->src_mac[5],
		((uint8_t*)&arpei->src_ip)[0], ((uint8_t*)&arpei->src_ip)[1],
		((uint8_t*)&arpei->src_ip)[2], ((uint8_t*)&arpei->src_ip)[3],
		arpei->dst_mac[0], arpei->dst_mac[1], arpei->dst_mac[2],
		arpei->dst_mac[3], arpei->dst_mac[4], arpei->dst_mac[5],
		((uint8_t*)&arpei->dst_ip)[0], ((uint8_t*)&arpei->dst_ip)[1],
		((uint8_t*)&arpei->dst_ip)[2], ((uint8_t*)&arpei->dst_ip)[3]);
#else
	printf("ARPOP: [ src_mac=%02x:%02x:%02x:%02x:%02x:%02x "
		"src_ip=%d.%d.%d.%d dst_mac=%02x:%02x:%02x:%02x:%02x:%02x "
		"dst_ip=%d.%d.%d.%d ]\n",
		arpei->src_mac[0], arpei->src_mac[1], arpei->src_mac[2],
		arpei->src_mac[3], arpei->src_mac[4], arpei->src_mac[5], 
		((uint8_t*)&arpei->src_ip)[0], ((uint8_t*)&arpei->src_ip)[1],
		((uint8_t*)&arpei->src_ip)[2], ((uint8_t*)&arpei->src_ip)[3],
		arpei->dst_mac[0], arpei->dst_mac[1], arpei->dst_mac[2],
		arpei->dst_mac[3], arpei->dst_mac[4], arpei->dst_mac[5],
		((uint8_t*)&arpei->dst_ip)[0], ((uint8_t*)&arpei->dst_ip)[1],
		((uint8_t*)&arpei->dst_ip)[2], ((uint8_t*)&arpei->dst_ip)[3]);
#endif
	
	q_decode_func = q_decode_data;
	return sizeof(*arpei);
}

void q_decode_ip_proto(uint32_t proto) {
	switch (proto) {
		case IPPROTO_ICMP:
			q_decode_func = q_decode_icmp;
			break;
			
		case IPPROTO_TCP:
			q_decode_func = q_decode_tcp;
			break;
			
		case IPPROTO_UDP:
			q_decode_func = q_decode_udp;
			break;
			
		case IPPROTO_IPV6:
			q_decode_func = q_decode_ipv6;
			break;
			
		default:
			q_decode_func = q_decode_data;
			break;
	}
}

int q_decode_ipv4(uint8_t *buf, uint32_t len) {
	struct ip *ip;

	ip = (struct ip*)buf;
	if (len < sizeof(*ip)) {
		q_decode_func = q_decode_data;
		return 0;
	}

#ifdef Q_DECODE_CONF_SHORT
	printf("IP %d.%d.%d.%d > %d.%d.%d.%d: ",
		((uint8_t*)&ip->ip_src)[0], ((uint8_t*)&ip->ip_src)[1],
		((uint8_t*)&ip->ip_src)[2], ((uint8_t*)&ip->ip_src)[3],
		((uint8_t*)&ip->ip_dst)[0], ((uint8_t*)&ip->ip_dst)[1],
		((uint8_t*)&ip->ip_dst)[2], ((uint8_t*)&ip->ip_dst)[3]);
#else
	printf("IP:    [ header-len=%d version=%d type=%d length=%d "
		"id=%d frag=%d ttl=%d protocal=%d checksum=%d "
		"from=%d.%d.%d.%d to=%d.%d.%d.%d ]\n",
		ip->ip_hl, ip->ip_v, ip->ip_tos,
		htons(ip->ip_len), htons(ip->ip_id),
		htons(ip->ip_off), ip->ip_ttl,
		ip->ip_p, htons(ip->ip_sum),
		((uint8_t*)&ip->ip_src)[0], ((uint8_t*)&ip->ip_src)[1],
		((uint8_t*)&ip->ip_src)[2], ((uint8_t*)&ip->ip_src)[3],
		((uint8_t*)&ip->ip_dst)[0], ((uint8_t*)&ip->ip_dst)[1],
		((uint8_t*)&ip->ip_dst)[2], ((uint8_t*)&ip->ip_dst)[3]);
#endif

	q_decode_ip_proto(ip->ip_p);
	return sizeof(*ip);
}

int q_decode_ipv6(uint8_t *buf, uint32_t len) {
	struct ip6_hdr *ip6;

	ip6 = (struct ip6_hdr*)buf;
	if (len < sizeof(*ip6)) {
		q_decode_func = q_decode_data;
		return 0;
	}

#ifdef Q_DECODE_CONF_SHORT
	printf("IPv6 %x:%x:%x:%x:%x:%x:%x:%x > %x:%x:%x:%x:%x:%x:%x:%x: ",
		htons(((uint16_t*)&ip6->ip6_src)[0]),
		htons(((uint16_t*)&ip6->ip6_src)[1]),
		htons(((uint16_t*)&ip6->ip6_src)[2]),
		htons(((uint16_t*)&ip6->ip6_src)[3]),
		htons(((uint16_t*)&ip6->ip6_src)[4]),
		htons(((uint16_t*)&ip6->ip6_src)[5]),
		htons(((uint16_t*)&ip6->ip6_src)[6]),
		htons(((uint16_t*)&ip6->ip6_src)[7]),
		htons(((uint16_t*)&ip6->ip6_dst)[0]),
		htons(((uint16_t*)&ip6->ip6_dst)[1]),
		htons(((uint16_t*)&ip6->ip6_dst)[2]),
		htons(((uint16_t*)&ip6->ip6_dst)[3]),
		htons(((uint16_t*)&ip6->ip6_dst)[4]),
		htons(((uint16_t*)&ip6->ip6_dst)[5]),
		htons(((uint16_t*)&ip6->ip6_dst)[6]),
		htons(((uint16_t*)&ip6->ip6_dst)[7]));
#else
	printf("IPv6:  [ flow=%d plen=%d nxt=%d hlim=%d "
		"vfc=0x%x src=%x:%x:%x:%x:%x:%x:%x:%x "
		"dest=%x:%x:%x:%x:%x:%x:%x:%x  ]\n",
		htonl(ip6->ip6_flow), htons(ip6->ip6_plen),
		ip6->ip6_nxt, ip6->ip6_hlim,
		ip6->ip6_ctlun.ip6_un2_vfc,
		htons(((uint16_t*)&ip6->ip6_src)[0]),
		htons(((uint16_t*)&ip6->ip6_src)[1]),
		htons(((uint16_t*)&ip6->ip6_src)[2]),
		htons(((uint16_t*)&ip6->ip6_src)[3]),
		htons(((uint16_t*)&ip6->ip6_src)[4]),
		htons(((uint16_t*)&ip6->ip6_src)[5]),
		htons(((uint16_t*)&ip6->ip6_src)[6]),
		htons(((uint16_t*)&ip6->ip6_src)[7]),
		htons(((uint16_t*)&ip6->ip6_dst)[0]),
		htons(((uint16_t*)&ip6->ip6_dst)[1]),
		htons(((uint16_t*)&ip6->ip6_dst)[2]),
		htons(((uint16_t*)&ip6->ip6_dst)[3]),
		htons(((uint16_t*)&ip6->ip6_dst)[4]),
		htons(((uint16_t*)&ip6->ip6_dst)[5]),
		htons(((uint16_t*)&ip6->ip6_dst)[6]),
		htons(((uint16_t*)&ip6->ip6_dst)[7]));
#endif

	q_decode_ip_proto(ip6->ip6_nxt);
	return sizeof(*ip6);
}

int q_decode_icmp(uint8_t *buf, uint32_t len) {
	struct icmp *icmp;

	icmp = (struct icmp*)buf;
	if (len < sizeof(*icmp)) {
		q_decode_func = q_decode_data;
		return 0;
	}

#ifdef Q_DECODE_CONF_SHORT
	printf("ICMP %d %d %d ",
		icmp->icmp_type,
		icmp->icmp_code,
		htons(icmp->icmp_cksum));
#else
	printf("ICMP:  [ type=%d code=%d checksum=%d ]\n",
		icmp->icmp_type, icmp->icmp_code,
		htons(icmp->icmp_cksum));
#endif

	q_decode_func = q_decode_data;
	return sizeof(*icmp);
}

int q_decode_tcp(uint8_t *buf, uint32_t len) {
	struct tcphdr *tcp;
	uint32_t tcpopt_len;

	tcp = (struct tcphdr*)buf;
	if (len < sizeof(*tcp)) {
		q_decode_func = q_decode_data;
		return 0;
	}

#ifdef Q_DECODE_CONF_SHORT
	printf("TCP %d %d (%d %d) ",
		htons(tcp->th_sport),
		htons(tcp->th_dport),
		htonl(tcp->th_seq),
		htonl(tcp->th_ack));
#else
	printf("TCP:   [ source-port=%d dest-port=%d "
		"seq=%d ack=%d offset=%d flags=",
		htons(tcp->th_sport), htons(tcp->th_dport),
		htonl(tcp->th_seq), htonl(tcp->th_ack),
		tcp->th_off);
#endif

	if ((tcp->th_flags & TH_FIN))
		printf("FIN ");
	if ((tcp->th_flags & TH_SYN))
		printf("SYN ");
	if ((tcp->th_flags & TH_RST))
		printf("RST ");
	if ((tcp->th_flags & TH_PUSH))
		printf("PUSH ");
	if ((tcp->th_flags & TH_ACK))
		printf("ACK ");
	if ((tcp->th_flags & TH_URG))
		printf("URG ");

#ifndef Q_DECODE_CONF_SHORT
	printf(" (%d) window=%d checksum=%d urgent=%d ]\n",
		       tcp->th_flags,
		       htons(tcp->th_win),
		       htons(tcp->th_sum),
		       htons(tcp->th_urp));

	tcpopt_len = (tcp->th_off * 4) - sizeof(*tcp);
	if (tcpopt_len) {
		uint32_t i, haslen;
		uint8_t *tcpopt;

		tcpopt = (uint8_t*)(buf + sizeof(*tcp));

		printf("TCPOP: [ ");
		for (i = 0; i < tcpopt_len;) {
			haslen = 0;
			switch (tcpopt[i]) {
				case TCPOPT_EOL:
					printf("EOL ");
					break;
					
				case TCPOPT_NOP:
					printf("NOP ");
					break;
					
				case TCPOPT_MAXSEG:
					printf("MAXSEG:%u ",
						htons(*(uint16_t*)(tcpopt + i + 2)));
					haslen = 1;
					break;
					
				case TCPOPT_WINDOW:
					printf("WINDOW:%u ", tcpopt[i+2]);
					haslen = 1;
					break;
					
				case TCPOPT_SACK_PERMITTED:
					printf("SACK_PERMIT ");
					haslen = 1;
					break;
					
				case TCPOPT_SACK:
					printf("SACK ");
					break;
					
				case TCPOPT_TIMESTAMP:
					printf("TIMESTAMP:%u:%u ",
						htonl(*(uint32_t*)(tcpopt + i + 2)),
						htonl(*(uint32_t*)(tcpopt + i + 6)));
					haslen = 1;
					break;
			}
			
			if (haslen && tcpopt[i+1] > 0)
				i += tcpopt[i+1];
			else
				i++;
		}
		printf("]\n");
	}
#endif

	q_decode_func = q_decode_data;
	return (tcp->th_off * 4);
}

int q_decode_udp(uint8_t *buf, uint32_t len) {
	struct udphdr *udp;

	udp = (struct udphdr*)buf;
	if (len < sizeof(*udp)) {
		q_decode_func = q_decode_data;
		return 0;
	}

#ifdef Q_DECODE_CONF_SHORT
	printf("UDP %d %d ",
		htons(udp->uh_sport),
		htons(udp->uh_dport));
#else
	printf("UDP:   [ source-port=%d dest-port=%d "
		"length=%d checksum=%d ]\n",
		htons(udp->uh_sport),
		htons(udp->uh_dport),
		htons(udp->uh_ulen),
		htons(udp->uh_sum));
#endif

	q_decode_func = q_decode_data;
	return sizeof(*udp);
}

int q_decode_data(uint8_t *buf, uint32_t len) {
#ifndef Q_DECODE_CONF_SHORT
#ifdef Q_DECODE_CONF_ASCII
	uint8_t *str, *ptr;
	int32_t n;

	str = malloc((len * 4) + 1);
	for (ptr = str, n = 0; n < len; n++) {
		if (isprint(buf[n])) {
			switch (buf[n]) {
				case '\\':
					*ptr++ = '\\';
					*ptr++ = '\\';
					break;
					
				case '"':
					*ptr++ = '\\';
					*ptr++ = '"';
					break;
					
				default:
					*ptr++ = buf[n];
					break;
			}
		}
		else {
			*ptr++ = '\\';
			switch (buf[n]) {
				case '\n':
					*ptr++ = 'n';
					break;
					
				case '\r':
					*ptr++ = 'r';
					break;
					
				case '\b':
					*ptr++ = 'b';
					break;
					
				case '\a':
					*ptr++ = 'a';
					break;
					
				case '\t':
					*ptr++ = 't';
					break;
					
				default:
					*ptr++ = 'x';
					ptr += sprintf((char*)ptr, "%02x", buf[n]);
					break;
			}
		}
	}
	*ptr++ = 0;
	printf("ASCII: [ \"%s\" ]\n", str);
	free(str);
#else
#ifdef Q_DECODE_CONF_HEX
	uint8_t *str, *ptr;
	int32_t n;

	str = malloc((len * 3) + 1);
	for (ptr = str, n = 0; n < len; n++)
		ptr += sprintf((char*)ptr, "%02x ", buf[n]);
	*ptr++ = 0;
	printf("HEX:   [ %s ]\n", str);
	free(str);
#endif
#endif
#endif

	q_decode_func = NULL;
	return 0;
}
