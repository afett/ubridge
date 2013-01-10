/*
 * UBridge: ring header
 *	By Benjamin Kittridge. Copyright (C) 2012, All rights reserved.
 *
 */

#pragma once

////////////////////////////////////////////////////////////////////////////////
// Section:     Required includes

#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <stdint.h>

////////////////////////////////////////////////////////////////////////////////
// Section:     Enums / Macros

enum {
	Q_RING_FRAME_SIZE =		2048,
	Q_RING_FRAME_PER_BLOCK =	4,
	Q_RING_BLOCK_COUNT =		1024,
	
	Q_RING_MTU =			ETH_DATA_LEN,
	Q_RING_MAX_FRAME =		ETH_FRAME_LEN + ETH_FCS_LEN,
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Structs / Typedefs

typedef struct q_ring_data {
	uint8_t *blk, *buf;
	struct tpacket2_hdr *hdr;
	struct sockaddr_ll *sll;
	uint32_t len;
} *q_ring_data_t;

typedef struct q_ring_group_t {
	int32_t fd;
	struct tpacket_req req;
	uint8_t *map;
	uint32_t map_len;
	q_ring_data_t r, r_start, r_end;
} *q_ring_group_t, q_ring_group_r[1];

typedef struct q_ring_t {
	int32_t ifindex, mtu, pending_write;
	q_ring_group_r rx, tx;
} *q_ring_t;

////////////////////////////////////////////////////////////////////////////////
// Section:     Public functions

q_ring_t q_ring_new(char *device);
void q_ring_setup(q_ring_t n, q_ring_group_t g, uint32_t direct);
void q_ring_bind(q_ring_t n, char *device);

q_ring_data_t q_ring_read(q_ring_t n);
void q_ring_ready(q_ring_data_t r);
void q_ring_write(q_ring_t n, uint8_t *buf, uint32_t len);
void q_ring_yield(q_ring_t n);
void q_ring_yield_dbl(q_ring_t n1, q_ring_t n2);
void q_ring_flush(q_ring_t n, bool block);

void q_ring_data_debug(q_ring_data_t r);

void q_ring_free(q_ring_t n);
