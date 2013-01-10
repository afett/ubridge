/*
 * UBridge: ring source
 *	By Benjamin Kittridge. Copyright (C) 2012, All rights reserved.
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#define __USE_XOPEN
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <features.h>
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#endif
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <string.h>
#include <netinet/in.h>
#include <signal.h>
#include "misc.h"
#include "ring.h"
#include "decode.h"

////////////////////////////////////////////////////////////////////////////////
// Class:       ring
// Description: Network packet ring

////////////////////////////////////////////////////////////////////////////////
// Section:     Ring setup

q_ring_t q_ring_new(char *device) {
	q_ring_t n;

	n = calloc(sizeof(*n), 1);
	q_ring_bind(n, device);
	q_ring_setup(n, n->rx, PACKET_RX_RING);
	q_ring_setup(n, n->tx, PACKET_TX_RING);
	return n;
}

void q_ring_setup(q_ring_t n, q_ring_group_t g, uint32_t direct) {
	struct sockaddr_ll addr;
	struct packet_mreq mr;
	q_ring_data_t ring;
	int32_t val, hdr_size, i;
	
	static_assert(Q_RING_FRAME_SIZE > Q_RING_MTU);
	
	if ((g->fd = socket(AF_PACKET, SOCK_RAW, 0)) < 0)
		error("socket: %s", strerror(errno));

	val = TPACKET_V2;
	if (setsockopt(g->fd, SOL_PACKET, PACKET_VERSION, &val, sizeof(val)) < 0)
		error("setsockopt: %s", strerror(errno));

	g->req.tp_frame_size = Q_RING_FRAME_SIZE;
	g->req.tp_block_size = Q_RING_FRAME_SIZE * Q_RING_FRAME_PER_BLOCK;
	g->req.tp_block_nr = Q_RING_BLOCK_COUNT;
	g->req.tp_frame_nr = Q_RING_BLOCK_COUNT * Q_RING_FRAME_PER_BLOCK;
	if ((setsockopt(g->fd, SOL_PACKET, direct, (char*)&g->req, sizeof(g->req))) < 0)
		error("setsockopt(%d): %s", direct, strerror(errno));

	g->map_len = g->req.tp_block_size * g->req.tp_block_nr;
	g->map = mmap(NULL, g->map_len, PROT_READ | PROT_WRITE, MAP_SHARED, g->fd, 0);
	if (g->map == MAP_FAILED)
		error("mmap: %s", strerror(errno));
	
	ring = calloc(g->req.tp_frame_nr * sizeof(*ring), 1);
	hdr_size = TPACKET_ALIGN(sizeof(*ring[0].hdr));
	for (i = 0; i < g->req.tp_frame_nr; i++) {
		ring[i].blk = g->map + (i * g->req.tp_frame_size);
		ring[i].hdr = (void*)(ring[i].blk);
		ring[i].sll = (void*)(ring[i].blk + hdr_size);
		ring[i].buf = (void*)(ring[i].blk + hdr_size);
		ring[i].len = g->req.tp_frame_size - hdr_size;
	}

	g->r_start = &ring[0];
	g->r_end = &ring[g->req.tp_frame_nr];
	g->r = g->r_start;

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_ifindex = n->ifindex;
	if (bind(g->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		error("bind: %s", strerror(errno));

	memset(&mr, 0, sizeof (mr));
	mr.mr_ifindex = n->ifindex;
	mr.mr_type = PACKET_MR_PROMISC;
	if (setsockopt(g->fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof (mr)) < 0)
		error("setsockopt: %s", strerror(errno));
}

void q_ring_bind(q_ring_t n, char *device) {
	struct ifreq s_ifr;
	struct ethtool_value eval;
	int32_t fd;
	
	if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0)
		error("socket: %s", strerror(errno));
	
	memset(&s_ifr, 0, sizeof(s_ifr));
	strncpy(s_ifr.ifr_name, device, sizeof(s_ifr.ifr_name));
	
	if (ioctl(fd, SIOCGIFINDEX, &s_ifr) < 0)
		error("ioctl: %s", strerror(errno));
	n->ifindex = s_ifr.ifr_ifindex;
	
	if (ioctl(fd, SIOCGIFMTU, &s_ifr) < 0)
		error("ioctl: %s", strerror(errno));
	n->mtu = s_ifr.ifr_mtu;
	
	if (n->mtu != Q_RING_MTU)
		error("Device %s has an is incorrect MTU (%u, should be %u)",
			device, n->mtu, Q_RING_MTU);
	
	if (ioctl(fd, SIOCGIFFLAGS, &s_ifr) < 0)
		error("ioctl: %s", strerror(errno));
	if ((s_ifr.ifr_flags & IFF_LOOPBACK))
		error("Device %s is a loopback device and cannot be bridged", device);
	if (!(s_ifr.ifr_flags & IFF_PROMISC)) {
		warning("Device %s has promisc mode disabled, enabling it", device);
		
		s_ifr.ifr_flags |= IFF_PROMISC;
		if (ioctl(fd, SIOCSIFFLAGS, &s_ifr) < 0)
			error("ioctl: %s", strerror(errno));
	}
	
	s_ifr.ifr_data = (void*)&eval;
	
	eval.cmd = ETHTOOL_GFLAGS;
	if (ioctl(fd, SIOCETHTOOL, &s_ifr) < 0)
		error("ioctl: %s", strerror(errno));
	if ((eval.data & ETH_FLAG_LRO)) {
		warning("Device %s has LRO enabled, disabling it", device);
		
		eval.cmd = ETHTOOL_SFLAGS;
		eval.data &= ~ETH_FLAG_LRO;
		if (ioctl(fd, SIOCETHTOOL, &s_ifr) < 0)
			error("ioctl: %s", strerror(errno));
	}
	
	eval.cmd = ETHTOOL_GGRO;
	if (ioctl(fd, SIOCETHTOOL, &s_ifr) < 0)
		error("ioctl: %s", strerror(errno));
	if (eval.data) {
		warning("Device %s has GRO enabled, disabling it", device);
		
		eval.cmd = ETHTOOL_SGRO;
		eval.data = 0;
		if (ioctl(fd, SIOCETHTOOL, &s_ifr) < 0)
			error("ioctl: %s", strerror(errno));
	}
	
	eval.cmd = ETHTOOL_GTSO;
	if (ioctl(fd, SIOCETHTOOL, &s_ifr) < 0)
		error("ioctl: %s", strerror(errno));
	if (eval.data) {
		warning("Device %s has TSO enabled, disabling it", device);
		
		eval.cmd = ETHTOOL_STSO;
		eval.data = 0;
		if (ioctl(fd, SIOCETHTOOL, &s_ifr) < 0)
			error("ioctl: %s", strerror(errno));
	}
	
	close(fd);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Ring receiving and transmission

q_ring_data_t q_ring_read(q_ring_t n) {
	q_ring_group_t g;
	q_ring_data_t r;
	
	g = n->rx;
	r = g->r;
	if (!r->hdr->tp_status)
		return NULL;
		
	__sync_synchronize();

	if (++g->r == g->r_end)
		g->r = g->r_start;
	return r;
}

void q_ring_ready(q_ring_data_t r) {
	r->hdr->tp_status = 0;
}

void q_ring_write(q_ring_t n, uint8_t *buf, uint32_t len) {
	q_ring_group_t g;
	q_ring_data_t r;
	
	g = n->tx;
	r = g->r;
	while (r->hdr->tp_status != TP_STATUS_AVAILABLE) {
		switch (r->hdr->tp_status) {
			case TP_STATUS_AVAILABLE:
				break;
				
			case TP_STATUS_SEND_REQUEST:
			case TP_STATUS_SENDING:
				q_ring_flush(n, true);
				usleep(0);
				break;
				
			case TP_STATUS_WRONG_FORMAT:
			default:
				error("An error has occured during transmission");
		}
	}
	
	if (len > r->len)
		error("Packet too large for transmission");
	memcpy(r->buf, buf, len);
	r->hdr->tp_len = len;
	r->hdr->tp_status = TP_STATUS_SEND_REQUEST;
		
	n->pending_write++;
	
	__sync_synchronize();
	
	if (++g->r == g->r_end)
		g->r = g->r_start;
}

void q_ring_yield(q_ring_t n) {
	struct pollfd pfd[1];
	
	pfd[0].fd = n->rx->fd;
	pfd[0].events = POLLIN;
	
	poll(pfd, sizearr(pfd), -1);
}

void q_ring_yield_dbl(q_ring_t n1, q_ring_t n2) {
	struct pollfd pfd[2];
	
	pfd[0].fd = n1->rx->fd;
	pfd[0].events = POLLIN;
	
	pfd[1].fd = n2->rx->fd;
	pfd[1].events = POLLIN;
	
	poll(pfd, sizearr(pfd), -1);
}

void q_ring_flush(q_ring_t n, bool block) {
	if (!block && !n->pending_write)
		return;
	if (sendto(n->tx->fd, NULL, 0, (block ? 0 : MSG_DONTWAIT), NULL, 0) < 0) {
		if (errno == ENOBUFS)
			warning("send: %s", strerror(errno));
		else
			error("send: %s", strerror(errno));
	}
	n->pending_write = 0;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Ring data

void q_ring_data_debug(q_ring_data_t r) {
#ifdef Q_RING_LONG_PARSE
	q_decode_parse(r->blk + r->hdr->tp_mac, r->hdr->tp_len);
#else
	static char *pkttype[] = { "<", "B", "M", "P", ">" };
	
	printf("%u.%09u: if%u %s %u bytes\n",
		r->hdr->tp_sec,
		r->hdr->tp_nsec,
		r->sll->sll_ifindex,
		pkttype[r->sll->sll_pkttype],
		r->hdr->tp_len);
#endif
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Ring destruction

void q_ring_free(q_ring_t n) {
	close(n->rx->fd);
	close(n->tx->fd);
	
	munmap(n->rx->map, n->rx->map_len);
	munmap(n->tx->map, n->tx->map_len);
	
	free(n);
}
