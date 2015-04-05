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
 * UBridge: bridge header
 *	By Benjamin Kittridge. Copyright (C) 2012, All rights reserved.
 *
 */

#pragma once

////////////////////////////////////////////////////////////////////////////////
// Section:     Required includes

#include <stdint.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include "ring.h"

////////////////////////////////////////////////////////////////////////////////
// Section:     Structs / Typedefs

typedef struct q_bridge_t {
	bool debug;
} *q_bridge_t;

////////////////////////////////////////////////////////////////////////////////
// Section:     Public functions

q_bridge_t q_bridge_new(bool debug);

void q_bridge_start(q_bridge_t b, char *src, char *dst);

void q_bridge_dispatch(q_bridge_t, q_ring_t n, q_ring_data_t r);

void q_bridge_checksum(uint8_t *buf, uint32_t len);
uint16_t q_bridge_checksum_ip(uint16_t *buf, uint32_t len);
uint16_t q_bridge_checksum_ip_proto(uint16_t *buf, uint16_t len, uint16_t proto,
		in_addr_t src_addr, in_addr_t dest_addr);

void q_bridge_free(q_bridge_t b);
