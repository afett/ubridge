/*
 * UBridge: decode header
 *	By Benjamin Kittridge. Copyright (C) 2012, All rights reserved.
 *
 */

#pragma once

////////////////////////////////////////////////////////////////////////////////
// Section:     Required includes

#include <stdint.h>
#include <netinet/in.h>

////////////////////////////////////////////////////////////////////////////////
// Section:     Structs / Typedefs

struct arpeihdr {
	uint8_t src_mac[ETH_ALEN];
	in_addr_t src_ip;
	uint8_t dst_mac[ETH_ALEN];
	in_addr_t dst_ip;
} __attribute((packed));

////////////////////////////////////////////////////////////////////////////////
// Section:     Config macros

#undef  Q_DECODE_CONF_SHORT
#undef  Q_DECODE_CONF_HEX
#define Q_DECODE_CONF_ASCII

////////////////////////////////////////////////////////////////////////////////
// Section:     Functions

void q_decode_parse(uint8_t *buf, uint32_t len);
int q_decode_pkt(uint8_t *buf, uint32_t len);
int q_decode_eth(uint8_t *buf, uint32_t len);
int q_decode_arp(uint8_t *buf, uint32_t len);
int q_decode_arp_eth_ip(uint8_t *buf, uint32_t len);
void q_decode_ip_proto(uint32_t proto);
int q_decode_ipv4(uint8_t *buf, uint32_t len);
int q_decode_ipv6(uint8_t *buf, uint32_t len);
int q_decode_icmp(uint8_t *buf, uint32_t len);
int q_decode_tcp(uint8_t *buf, uint32_t len);
int q_decode_udp(uint8_t *buf, uint32_t len);
int q_decode_data(uint8_t *buf, uint32_t len);
