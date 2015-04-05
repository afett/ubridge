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
 * UBridge: main source
 *	By Benjamin Kittridge. Copyright (C) 2012, All rights reserved.
 *
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <getopt.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "misc.h"
#include "bridge.h"

////////////////////////////////////////////////////////////////////////////////
// Class:       main
// Description: Network bridge

////////////////////////////////////////////////////////////////////////////////
// Section:     Options
// Description: Parses getopt() options

enum {
	OPTION_DEBUG,
	OPTION_SRC,
	OPTION_DST,

	OPTION_HELP,
	OPTION_VERSION,
};

static struct option option_fields[] = {
	{ "debug",		0,	0,	OPTION_DEBUG			},
	{ "src",		1,	0,	OPTION_SRC			},
	{ "dst",		1,	0,	OPTION_DST			},

	{ "help",		0,	0,	OPTION_HELP			},
	{ "version",		0,	0,	OPTION_VERSION			},
	{ NULL,			0,	0,	0				}
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Static information
// Description: Prints help and version information when requested

void help() {
	printf("\n");
	printf("Usage: ubridge [OPTIONS]...\n");
	printf("\t%-25s Run in foreground and print packets\n",	"--debug");
	printf("\t%-25s Source interface\n",			"--src [if]");
	printf("\t%-25s Destination interface\n",		"--dst [if]");
	printf("\t%-25s Displays this help screen\n",		"--help");
	printf("\t%-25s Displays version information\n",	"--version");
	printf("\n");
	printf("Example:  ubridge --debug --src vif1.0 --dst eth0\n");
	printf("\n");
	exit(1);
}

void version() {
	printf("UBridge version "VERSION", build on "__DATE__" "__TIME__"\n");
	printf("Copyright 2012 Benjamin Kittridge. All rights reserved.\n");
	exit(1);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Initialization
// Description: Parse command line and start the bridge

int main(int argc, char **argv) {
	int32_t c;
	char *src, *dst;
	bool debug;
	q_bridge_t b;

	src = NULL;
	dst = NULL;
	debug = false;
	b = NULL;

	while (1) {
		if ((c = getopt_long_only(argc, argv, "", option_fields, NULL)) < 0)
			break;

		// Process each option returned
		switch (c) {
			case OPTION_DEBUG:
				debug = true;
				break;

			case OPTION_SRC:
				src = optarg;
				break;

			case OPTION_DST:
				dst = optarg;
				break;

			case OPTION_HELP:
				help();
				break;

			case OPTION_VERSION:
				version();
				break;

			default:
				warning("Unknown or invalid option at \"%s\" (%d)", argv[optind], c);
				help();
				break;
		}
	}

	// The user entered non-option data
	if (optind != argc) {
		warning("Unknown or invalid option at \"%s\"", argv[optind]);
		help();
		return 0;
	}

	if (!src) {
		warning("Must specify source interface using --src");
		help();
		return 0;
	}

	if (!dst) {
		warning("Must specify destination interface using --dst");
		help();
		return 0;
	}

	// If debugging is turned off, fork process into the background and close fd's
	if (!debug) {
		if (daemon(1, 0) < 0)
			error("Error forking process");
	}

	b = q_bridge_new(debug);

	// Main bridge loop
	q_bridge_start(b, src, dst);
	q_bridge_free(b);
	return 0;
}
