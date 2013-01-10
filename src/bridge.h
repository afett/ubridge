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
// Section:     Public functions

void q_bridge_start(char *src, char *dst, bool debug);

void q_bridge_dispatch(q_ring_t n, q_ring_data_t r);

void q_bridge_checksum(uint8_t *buf, uint32_t len);
uint16_t q_bridge_checksum_ip(uint16_t *buf, uint32_t len);
uint16_t q_bridge_checksum_ip_proto(uint16_t *buf, uint16_t len, uint16_t proto,
		in_addr_t src_addr, in_addr_t dest_addr);
