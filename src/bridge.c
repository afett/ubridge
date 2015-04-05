/*
 * Copyright (c) 2015 Andreas Fett.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

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
#include <sys/epoll.h>
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
// Section:     Prototypes for private methods
static void q_bridge_dispatch(q_bridge_t b, q_ring_t n, q_ring_data_t r);
static void q_bridge_checksum(uint8_t *buf, uint32_t len);
static uint16_t q_bridge_checksum_ip(uint16_t *buf, uint32_t len);
static uint16_t q_bridge_checksum_ip_proto(uint16_t *buf, uint16_t len, uint16_t proto,
		in_addr_t src_addr, in_addr_t dest_addr);
static void q_bridge_drain_ring(q_bridge_t b, size_t idx);

////////////////////////////////////////////////////////////////////////////////
// Section:     Create a new bridge

q_bridge_t q_bridge_new(bool debug)
{
	q_bridge_t n;
	n = calloc(sizeof(*n), 1);
	n->debug = debug;
	n->epollfd = epoll_create1(0);
	if (n->epollfd < 0) {
		error("Failed to create epoll fd: %s", strerror(errno));
	}
	return n;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Add bridge interface

void q_bridge_add(q_bridge_t b, const char *ifname)
{
	q_ring_t n;
	struct epoll_event ev;

	if (b->nrings == sizearr(b->ring)) {
		error("Can't add interface, max size is %zu", sizearr(b->ring));
	}

	// Create a ring for the new interface
	n = q_ring_new(ifname);
	ev.events = EPOLLIN;
	ev.data.u64 = b->nrings;
	if (epoll_ctl(b->epollfd, EPOLL_CTL_ADD, n->tx->fd, &ev) != 0) {
		error("Failed to add fd to epoll set: %s", strerror(errno));
	}
	b->ring[b->nrings] = n;
	++b->nrings;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Start bridge
// Description: The bridge loop reads from each ring and writes to it's
//              counterpart

void q_bridge_start(q_bridge_t b) {
	struct epoll_event ev[Q_BRIGE_MAXIF];
	int nfd, i;

	if (b->nrings < 2) {
		error("Can't start, only have %zu interfaces", b->nrings);
		// no return
	}

	while (1) {
		// Yield until data is available on either interface
		nfd = epoll_wait(b->epollfd, ev, b->nrings, -1);
		if (nfd <= 0) {
			error("error in epoll_wait: %s", strerror(errno));
		}

		for (i = 0; i < nfd; ++i) {
			if (ev[i].events & EPOLLIN) {
				q_bridge_drain_ring(b, ev[i].data.u64);
			}
		}
	}

	// Cannot be reached
}

static void q_bridge_drain_ring(q_bridge_t b, size_t idx)
{
	q_ring_data_t r;
	size_t didx;

	// Read from source interface and dispatch results (q_ring_data_t)
	// to destination interface
	while ((r = q_ring_read(b->ring[idx]))) {
		for (didx = 0; didx < b->nrings; ++didx) {
			if (didx == idx) {
				continue;
			}
			q_bridge_dispatch(b, b->ring[didx], r);
		}
		q_ring_ready(r);
	}

	// Flushes dest ring if data was dispatched to it
	for (didx = 0; didx < b->nrings; ++didx) {
		if (didx == idx) {
			continue;
		}
		q_ring_flush(b->ring[didx], false);
	}
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Dispatch packet
// Description: Writes packet to target ring

static void q_bridge_dispatch(q_bridge_t b, q_ring_t n, q_ring_data_t r) {
	uint8_t *buf;
	uint32_t len;

	// Determine if packet type matches a packet that we should
	// relay to target ring
	if (r->sll->sll_pkttype != PACKET_HOST &&
	    r->sll->sll_pkttype != PACKET_MULTICAST &&
	    r->sll->sll_pkttype != PACKET_BROADCAST &&
	    r->sll->sll_pkttype != PACKET_OTHERHOST)
		return;

	// Print packet if debugging is enabled
	if (b->debug)
		q_ring_data_debug(r);

	// Point the buffer to the correct location
	buf = r->blk + r->hdr->tp_mac;
	len = r->hdr->tp_len;

	// At this point, tp_snaplen = tp_len and tp_snaplen should fit on a
	// single frame, does not support fragmentation
	if (len != r->hdr->tp_snaplen || len > Q_RING_MAX_FRAME)
		error("Packet too large (len = %u / %u)", len, r->hdr->tp_snaplen);

	// If checksum is not ready (usually happens when receiving a packet
	// from a virtual interface, calculate ip checksum
	if ((r->hdr->tp_status & TP_STATUS_CSUMNOTREADY))
		q_bridge_checksum(buf, len);

	// Write packet to target ring
	q_ring_write(n, buf, len);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Checksuming
// Description: Must checksum packets where status contains TP_STATUS_CSUMNOTREADY

// Macro that sets the header to the front of the buffer while incrementing
// the pointer to the the length of the header
#define POP_HEADER(_var, _buf, _len) ({			\
		_var = (void *)_buf;			\
		(_len >= sizeof(*_var) ? 		\
			_buf += sizeof(*_var),		\
			_len -= sizeof(*_var),		\
			true : false);			\
	})

static void q_bridge_checksum(uint8_t *buf, uint32_t len) {
	struct ethhdr *eth;
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct udphdr *udp;
	struct icmphdr *icmp;

	// Pop ethernet header and increment buffer
	if (!POP_HEADER(eth, buf, len))
		return;

	// Checksum routine only supports IP packets
	if (htons(eth->h_proto) != ETH_P_IP)
		return;

	// Pop IP header
	if (!POP_HEADER(ip, buf, len))
		return;
	// Calculate IP checksum using one's complement
	ip->check = 0;
	ip->check = q_bridge_checksum_ip((uint16_t*)ip, sizeof(*ip));

	// Calculate checksum for various IP protocols
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

static uint16_t q_bridge_checksum_ip(uint16_t *buf, uint32_t len) {
	uint32_t sum;
	uint16_t *w;
	uint32_t nleft;

	// One's complement checksum routine
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

static uint16_t q_bridge_checksum_ip_proto(uint16_t *buf, uint16_t len, uint16_t proto,
		in_addr_t src_addr, in_addr_t dest_addr) {
	uint16_t *ip_src, *ip_dst;
	uint32_t sum;
	uint16_t length;

	// Checksum is usually derived from pseudo-header of IP protocol, but
	// a better way would be to simply include the header in place
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

////////////////////////////////////////////////////////////////////////////////
// Section:     Brdige destruction
// Description: Close fd and free memory

void q_bridge_free(q_bridge_t b)
{
	size_t idx;
	for (idx = 0; idx < b->nrings; ++idx) {
		q_ring_free(b->ring[idx]);
	}
	close(b->epollfd);
	free(b);
}
