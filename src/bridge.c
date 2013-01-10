/*
 * UBridge: bridge source
 *	By Benjamin Kittridge. Copyright (C) 2012, All rights reserved.
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include "misc.h"
#include "ring.h"
#include "bridge.h"
#include "decode.h"

////////////////////////////////////////////////////////////////////////////////
// Class:       bridge
// Description: Network bridge

////////////////////////////////////////////////////////////////////////////////
// Section:     Global variables

static bool q_bridge_debug = false;

////////////////////////////////////////////////////////////////////////////////
// Section:     Start bridge

void q_bridge_start(char *src, char *dst, bool debug) {
	q_ring_t n, k;
	q_ring_data_t r;
	
	q_bridge_debug = debug;
	
	n = q_ring_new(src);
	k = q_ring_new(dst);
	
	while (1) {
		while ((r = q_ring_read(n))) {
			q_bridge_dispatch(k, r);
			q_ring_ready(r);
		}
		while ((r = q_ring_read(k))) {
			q_bridge_dispatch(n, r);
			q_ring_ready(r);
		}
		
		q_ring_flush(n, false);
		q_ring_flush(k, false);
		
		q_ring_yield_dbl(n, k);
	}
	
	q_ring_free(n);
	q_ring_free(k);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Dispatch packet

void q_bridge_dispatch(q_ring_t n, q_ring_data_t r) {
	uint8_t *buf;
	uint32_t len;
	
	if (r->sll->sll_pkttype != PACKET_HOST &&
	    r->sll->sll_pkttype != PACKET_MULTICAST &&
	    r->sll->sll_pkttype != PACKET_BROADCAST &&
	    r->sll->sll_pkttype != PACKET_OTHERHOST)
		return;
	
	if (q_bridge_debug)
		q_ring_data_debug(r);

	buf = r->blk + r->hdr->tp_mac;
	len = r->hdr->tp_len;
	
	if (len != r->hdr->tp_snaplen || len > Q_RING_MAX_FRAME)
		error("Packet too large (len = %u / %u)", len, r->hdr->tp_snaplen);

	if ((r->hdr->tp_status & TP_STATUS_CSUMNOTREADY))
		q_bridge_checksum(buf, len);
		
	q_ring_write(n, buf, len);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Checksuming

#define POP_HEADER(_var, _buf, _len) ({			\
		_var = (void *)_buf;			\
		(_len >= sizeof(*_var) ? 		\
			_buf += sizeof(*_var),		\
			_len -= sizeof(*_var),		\
			true : false);			\
	})

void q_bridge_checksum(uint8_t *buf, uint32_t len) {
	struct ethhdr *eth;
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct udphdr *udp;
	struct icmphdr *icmp;

	if (!POP_HEADER(eth, buf, len))
		return;
	if (htons(eth->h_proto) != ETH_P_IP)
		return;

	if (!POP_HEADER(ip, buf, len))
		return;
	ip->check = 0;
	ip->check = q_bridge_checksum_ip((uint16_t*)ip, sizeof(*ip));
	
	switch (ip->protocol) {
		case IPPROTO_TCP:
			if (!POP_HEADER(tcp, buf, len))
				return;
			tcp->check = 0;
			tcp->check = q_bridge_checksum_ip_proto((uint16_t*)tcp, sizeof(*tcp) + len,
					IPPROTO_TCP, ip->saddr, ip->daddr);
			break;
			
		case IPPROTO_UDP:
			if (!POP_HEADER(udp, buf, len))
				return;
			udp->check = 0;
			udp->check = q_bridge_checksum_ip_proto((uint16_t*)udp, sizeof(*udp) + len,
					IPPROTO_UDP, ip->saddr, ip->daddr);
			break;
			
		case IPPROTO_ICMP:
			if (!POP_HEADER(icmp, buf, len))
				return;
			icmp->checksum = 0;
			icmp->checksum = q_bridge_checksum_ip_proto((uint16_t*)icmp, sizeof(*icmp) + len,
					IPPROTO_ICMP, ip->saddr, ip->daddr);
			break;
	}
}

uint16_t q_bridge_checksum_ip(uint16_t *buf, uint32_t len) {
	uint32_t sum;
	uint16_t *w;
	uint32_t nleft;
	
	sum = 0;
	nleft = len;
	w = buf;
	
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft > 0)
		sum += *w & 0xFF;
	
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	return ~sum;
}

uint16_t q_bridge_checksum_ip_proto(uint16_t *buf, uint16_t len, uint16_t proto,
		in_addr_t src_addr, in_addr_t dest_addr) {
	uint16_t *ip_src, *ip_dst;
	uint32_t sum;
	uint16_t length;
	
	sum = 0;
	length = len;
	ip_src = (uint16_t*)&src_addr;
	ip_dst = (uint16_t*)&dest_addr;
	
	while (len > 1) {
		sum += *buf++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}
	
	if (len & 1)
		sum += *((uint8_t*)buf);
	
	sum += *(ip_src++);
	sum += *ip_src;
	sum += *(ip_dst++);
	sum += *ip_dst;
	sum += htons(proto);
	sum += htons(length);
	
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	
	return ((uint16_t)(~sum));
}
