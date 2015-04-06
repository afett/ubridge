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

#include "ring.h"

////////////////////////////////////////////////////////////////////////////////
// Section:     Enums / Macros

enum {
	Q_BRIGE_MAXIF = 16,
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Structs / Typedefs

typedef struct q_port_t {
	bool learning;
	uint8_t lladdr[ETH_ALEN];
	q_ring_t ring;
} q_port_t;

typedef struct q_bridge_t {
	bool debug;
	int epollfd;
	size_t nports;
	q_port_t port[Q_BRIGE_MAXIF];
} *q_bridge_t;

////////////////////////////////////////////////////////////////////////////////
// Section:     Public functions

q_bridge_t q_bridge_new(bool debug);

void q_bridge_add(q_bridge_t b, const char *ifname);

void q_bridge_start(q_bridge_t b);

void q_bridge_free(q_bridge_t b);
