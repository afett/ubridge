/*
 * UBridge: misc header
 *	By Benjamin Kittridge. Copyright (C) 2012, All rights reserved.
 *
 */

#pragma once

////////////////////////////////////////////////////////////////////////////////
// Section:     Macros

#ifndef sizearr
#define sizearr(a) (sizeof(a) / sizeof(*a))
#endif

#define warning(f, x...)			\
	printf("WARNING: "f"\n", ##x)

#define error(f, x...)				\
	do {					\
		printf("ERROR: "f"\n", ##x);	\
		exit(1);			\
	} while(0)

#define static_assert(c)			\
	switch (0) { case 0: case (c): ; }

