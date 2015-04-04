#
#  Makefile
#	By Benjamin Kittridge. Copyright (C) 2011, All rights reserved.
#
#

###################################################
# Options

NAME =		ubridge
VERSION =	1.0

BIN_PATH =	bin
BIN =		ubridge

SRC_PATH =	src
SRC =		$(patsubst %.c,%.o,$(wildcard ${SRC_PATH}/*.c)) \
		$(patsubst %.c,%.o,$(wildcard ${SRC_PATH}/*/*.c)) \
		$(patsubst %.c,%.o,$(wildcard ${SRC_PATH}/*/*/*.c))

LINK_ARG =	-pthread
COMPILE_ARG =	-g -iquote ${SRC_PATH} -Wimplicit -Wall -Wextra \
		--std=gnu99 -DVERSION=\"${VERSION}\"

###################################################
# Programs

ECHO =		echo
GCC =		gcc
RM =		rm
MKDIR =		mkdir

###################################################
# Build

all: info build

info:
	@${ECHO} "BUILDING: ${NAME}"

-include $(SRC:.o=.d)

.SUFFIXES:
.SUFFIXES: .c .so .o
.c.o:
	@${ECHO} "COMPILE:  $<"
	@${GCC} -MD -c $< -o $@ ${COMPILE_ARG}

build: ${SRC}
	@${MKDIR} -p ${BIN_PATH}
	@${ECHO} "LINK:     ${BIN_PATH}/${BIN}"
	@${GCC} -o ${BIN_PATH}/${BIN} ${SRC} ${LINK_ARG}
	@${ECHO}
	
clean:
	@${RM} -f ${BIN_PATH}/${BIN} ${SRC} $(SRC:.o=.d)
