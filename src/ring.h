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

q_ring_t q_ring_new(const char *device);

q_ring_data_t q_ring_read(q_ring_t n);
void q_ring_ready(q_ring_data_t r);
void q_ring_write(q_ring_t n, uint8_t *buf, uint32_t len);
void q_ring_yield_dbl(q_ring_t n1, q_ring_t n2);
void q_ring_flush(q_ring_t n, bool block);

void q_ring_data_debug(q_ring_data_t r);

void q_ring_free(q_ring_t n);
